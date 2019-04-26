use box_::{PublicKey, PUBLICKEYBYTES};
use pwhash::{MemLimit, OpsLimit, Salt, SALTBYTES};
use secretbox::{Key, Nonce, KEYBYTES, NONCEBYTES};
use sodiumoxide::crypto::{box_, pwhash, secretbox};
use sodiumoxide::utils::memzero;
use std::mem;

// Technology for Encrypted Resting Data

pub const DEFAULT_OPSLIMIT: OpsLimit = pwhash::scryptsalsa208sha256::OPSLIMIT_INTERACTIVE;
pub const DEFAULT_MEMLIMIT: MemLimit = pwhash::scryptsalsa208sha256::MEMLIMIT_INTERACTIVE;

pub enum Keystore {
    Locked(LockedKeystore),
    Unlocked(UnlockedKeystore),
}

#[derive(Debug,PartialEq)]
pub struct LockedKeystore {
    public_key: PublicKey,
    encrypted_secret_key: Vec<u8>,
    secretbox_nonce: Nonce,
    kdf_salt: Salt,
}

#[derive(Debug,PartialEq)]
pub struct UnlockedKeystore {
    keystore: LockedKeystore,
    secret_key: Vec<u8>,
}

impl Drop for UnlockedKeystore {
    fn drop(&mut self) {
        // zero out the memory where we stored the secret key
        memzero(&mut self.secret_key);
    }
}

impl LockedKeystore {
    pub fn from_password(password: &[u8]) -> Result<LockedKeystore, ()> {
        let (public_key, secret_key) = box_::gen_keypair();
        let kdf_salt = pwhash::gen_salt();
        let secretbox_nonce = secretbox::gen_nonce();
        let secretbox_key = password_kdf(password, &kdf_salt)?;

        Ok(LockedKeystore {
            public_key,
            secretbox_nonce,
            kdf_salt,
            encrypted_secret_key: secretbox::seal(&secret_key.0, &secretbox_nonce, &secretbox_key),
        })
    }

    pub fn empty() -> LockedKeystore {
        LockedKeystore {
            public_key: PublicKey([0u8; PUBLICKEYBYTES]),
            encrypted_secret_key: Vec::new(),
            secretbox_nonce: Nonce([0u8; NONCEBYTES]),
            kdf_salt: Salt([0u8; SALTBYTES]),
        }
    }

    pub fn unlock(self, password: &[u8]) -> Result<UnlockedKeystore,()> {
        let secretbox_key = password_kdf(password, &self.kdf_salt)?;
        let secret_key = secretbox::open(&self.encrypted_secret_key, &self.secretbox_nonce, &secretbox_key)?;

        Ok(UnlockedKeystore {
            keystore: self,
            secret_key,
        })
    }
}

impl UnlockedKeystore {
    pub fn lock(mut self) -> LockedKeystore {
        // we use mem::replace here so that we can take ownership of keystore
        // even though `LockedKeystore` implements Drop (which zeroes out the sk)
        mem::replace(& mut self.keystore, LockedKeystore::empty())
    }
}

fn password_kdf(password: &[u8], salt: &Salt) -> Result<Key, ()> {
    let mut key = Key([0; KEYBYTES]);
    let Key(ref mut key_bytes) = key;
    let slice = pwhash::derive_key(
        key_bytes,
        password,
        salt,
        DEFAULT_OPSLIMIT,
        DEFAULT_MEMLIMIT,
    )?;
    assert_eq!(slice.len(), KEYBYTES);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASSWORD: &[u8] = b"open sesame";

    #[test]
    fn constructing_locked_keystore_from_password() {
        let locked_keystore = LockedKeystore::from_password(PASSWORD).unwrap();
        assert_eq!(locked_keystore.encrypted_secret_key.len(), 48);
    }

    #[test]
    fn deriving_key_from_password() {
        let salt = Salt([
            102, 81, 127, 206, 128, 216, 34, 179, 98, 193, 143, 227, 153, 167, 228, 83, 228, 74,
            164, 53, 151, 241, 126, 168, 30, 130, 84, 203, 155, 78, 109, 174,
        ]);
        let Key(key_bytes) = password_kdf(PASSWORD, &salt).unwrap();
        assert_eq!(
            key_bytes,
            [
                173, 163, 64, 22, 249, 146, 68, 16, 134, 31, 144, 28, 204, 50, 223, 179, 253, 176,
                35, 176, 92, 15, 62, 136, 160, 19, 85, 44, 237, 28, 88, 82
            ]
        );
    }

    #[test]
    fn locking_and_unlocking_keystore() {

        let locked_keystore1 = LockedKeystore::from_password(PASSWORD).unwrap();
        let encrypted_secret_key1 = locked_keystore1.encrypted_secret_key.clone();

        let unlocked_keystore1 = locked_keystore1.unlock(PASSWORD).unwrap();
        let secret_key1 = unlocked_keystore1.secret_key.clone();

        let locked_keystore2 = unlocked_keystore1.lock();
        let encrypted_secret_key2 = locked_keystore2.encrypted_secret_key.clone();
        let secret_key2 = locked_keystore2.unlock(PASSWORD).unwrap().secret_key.clone();

        assert_eq!(
            secret_key1,
            secret_key2
        );

        assert_eq!(
            encrypted_secret_key1,
            encrypted_secret_key2,
        );

        assert_ne!(
            secret_key1,
            encrypted_secret_key1,
        );

        assert_ne!(
            secret_key2,
            encrypted_secret_key2,
        );
    }

    #[test]
    #[ignore]
    fn zeroing_out_secret_key_bytes_after_locking_keystore() {
        // PENDING
    }
}
