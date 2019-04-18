# FOREST

FOREST (Functionally Obsucated Resting Encryption Storage Technology) is an attempt at a generalized version of Riseup's [TREES](https://0xacab.org/riseuplabs/trees) re-written in Rust.

TREES encrypts a user's emails to a public key whose private key may only be decrypted by the logged-in user. It uses a KDF (NaCl's argon2 digest implementation) to derive a symmetric key from the user's password. It then uses this symmetric key to encrypt the user's private key at rest when the user is logged out. When a user logs in, their password is passed through the KDF to re-generate the symetric key, which is used to decrypt the user's private key, which is in turn used to decrypt the email data which has been encrypted to the user's public key.

Our hope is to:

1. Rewrite the logic that TREES uses to interact with Dovecot in Rust
1. Provide generalized interfaces that could be used to encrypt arbitrary data at rest
1. Learn some stuff!
