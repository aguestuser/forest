# TERD (Technology for Encrypting Resting Data)

This is an attempt at a generalized version of Riseup's [TREES](https://0xacab.org/riseuplabs/trees) library written in Rust. TREES encrypts user emails to a public key whose private key may only be decrypted by a logged-in user. (It stores the private key as an argon2 digest of the user's password.)

The hope is to:

1. Rewrite the logic that TREES uses to interact with Dovecot in Rust
1. Provide generalized interfaces that could be used to encrypt arbitrary data at rest
1. Learn some stuff in case we don't finish!
