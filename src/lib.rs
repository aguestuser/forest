use sodiumoxide::crypto::pwhash::argon2id13;
use argon2id13::{OpsLimit,MemLimit,HashedPassword};

// Technology for Encrypted Resting Data Storage
// TERDS

// Technology for Resting Email Encryption Storage


/**
 * consume: password
 * generate:
 * - encrypted priv key
 * - nonce
 * - public key
 * ->
 *
 */

const DEFAULT_OPSLIMIT: OpsLimit = argon2id13::OPSLIMIT_MODERATE;
const DEFAULT_MEMLIMIT: MemLimit = argon2id13::MEMLIMIT_MODERATE;

type HashParams = (OpsLimit, MemLimit);

enum Keystore {
    Locked(LockedKeystore),
    Unlocked(UnlockedKeystore),
}

struct LockedKeystore {
    public_key: Vec<u8>,
    encrypted_secret_key: Vec<u8>,
    secret_key_nonce: Vec<u8>, // FIXME: key size?
    pwhash_opslimit: OpsLimit,
    pwhash_memlimit: MemLimit,
    pwhash_salt: Vec<u8>,
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
    fn from_password(password: &[u8], hash_params: Option<HashParams>) -> Result<LockedKeystore, ()> {
        let (opslimit, memlimit) = hash_params.unwrap_or((DEFAULT_OPSLIMIT, DEFAULT_MEMLIMIT));
        let pwhash = argon2id13::pwhash(password, opslimit, memlimit)?;
        
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_pwhash() {
        
    }
}
