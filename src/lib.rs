use box_::{PublicKey, SecretKey, PUBLICKEYBYTES, SECRETKEYBYTES};
use pwhash::{MemLimit, OpsLimit, Salt, SALTBYTES};
use secretbox::{Key, Nonce, KEYBYTES, NONCEBYTES};
use sodiumoxide::crypto::{box_, pwhash, secretbox};

// Technology for Encrypted Resting Data

const DEFAULT_OPSLIMIT: OpsLimit = pwhash::scryptsalsa208sha256::OPSLIMIT_INTERACTIVE;
const DEFAULT_MEMLIMIT: MemLimit = pwhash::scryptsalsa208sha256::MEMLIMIT_INTERACTIVE;

type HashParams = (OpsLimit, MemLimit);

enum Keystore {
    Locked(LockedKeystore),
    Unlocked(UnlockedKeystore),
}

struct LockedKeystore {
    pk_bytes: [u8; PUBLICKEYBYTES],
    encrypted_sk: Vec<u8>,
    sk_nonce_bytes: [u8; NONCEBYTES],
    pwhash_salt_bytes: [u8; SALTBYTES],
}

struct UnlockedKeystore {
    keystore: LockedKeystore,
    secret_key: Vec<u8>,
}

impl Drop for UnlockedKeystore {
    fn drop(&mut self) {
        unimplemented!();
    }
}

impl LockedKeystore {
    fn from_password(password: &[u8]) -> Result<LockedKeystore, ()> {
        let (PublicKey(pk_bytes), SecretKey(sk_bytes)) = box_::gen_keypair();
        let Salt(pwhash_salt_bytes) = pwhash::gen_salt();
        let Nonce(sk_nonce_bytes) = secretbox::gen_nonce();
        let secretbox_key = password_kdf(password, &Salt(pwhash_salt_bytes))?;

        Ok(LockedKeystore {
            pk_bytes,
            sk_nonce_bytes,
            pwhash_salt_bytes,
            encrypted_sk: secretbox::seal(&sk_bytes, &Nonce(sk_nonce_bytes), &secretbox_key),
        })
    }
    fn unlock(self) -> UnlockedKeystore {
        unimplemented!("TODO")
    }
}

impl UnlockedKeystore {
    fn lock(self) -> LockedKeystore {
        unimplemented!("TODO")
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
    const password: &'static str = "open sesame";

    #[test]
    fn test_constructing_locked_keystore_from_password() {
        let locked_keystore = LockedKeystore::from_password(password.as_bytes());
    }

    #[test]
    fn derive_key_from_password() {
        let salt = Salt([
            102, 81, 127, 206, 128, 216, 34, 179, 98, 193, 143, 227, 153, 167, 228, 83, 228, 74,
            164, 53, 151, 241, 126, 168, 30, 130, 84, 203, 155, 78, 109, 174,
        ]);
        let Key(key_bytes) = password_kdf(password.as_bytes(), &salt).unwrap();
        assert_eq!(
            key_bytes,
            [
                173, 163, 64, 22, 249, 146, 68, 16, 134, 31, 144, 28, 204, 50, 223, 179, 253, 176,
                35, 176, 92, 15, 62, 136, 160, 19, 85, 44, 237, 28, 88, 82
            ]
        );
    }

    #[test]
    fn lock_and_unlock_a_keystore() {
        unimplemented!("TODO");
    }
}
