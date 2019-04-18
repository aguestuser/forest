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
        let (Salt(pwhash_salt_bytes), Nonce(sk_nonce_bytes)) =
            (pwhash::gen_salt(), secretbox::gen_nonce());
        let secretbox_key = password_kdf(password, &Salt(pwhash_salt_bytes))?;

        Ok(LockedKeystore {
            pk_bytes,
            sk_nonce_bytes,
            pwhash_salt_bytes,
            encrypted_sk: secretbox::seal(&sk_bytes, &Nonce(sk_nonce_bytes), &secretbox_key),
        })
    }

}

fn password_kdf(password: &[u8], salt: &Salt) -> Result<Key, ()> {
    let mut key = Key([0; secretbox::KEYBYTES]);
    let Key(ref mut key_bytes) = key;
    pwhash::derive_key(
        key_bytes,
        password,
        salt,
        DEFAULT_OPSLIMIT,
        DEFAULT_MEMLIMIT,
    )?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constructing_locked_keystore_from_password() {
        let password = String::from("open sesame");
        let locked_keystore = LockedKeystore::from_password(password.as_bytes());
        assert!(true);
    }
}
