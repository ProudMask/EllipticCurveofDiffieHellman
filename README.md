# Elliptic Curve Diffie–Hellman Learning Demo

A runnable, in-memory key-agreement and authenticated-encryption example using the cryptography library. Alice and Bob independently compute a shared secret with ECDH, derive a 32-byte key using HKDF-SHA256, then round-trip a synthetic message using AES-256-GCM.

## Run

Python 3.10 or later:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python ecdh_demo.py
python -m unittest discover -s tests -v
```

The JSON report should show derived_keys_match and round_trip_verified as true. It prints algorithm names and byte counts, not private keys, shared secrets, derived keys, or message contents. Key pairs, salt, and nonce are freshly generated each run; results are verified by properties rather than fixed ciphertext. No files or network connections are created by the demo.

An optional `--message` accepts synthetic text. Avoid putting real secrets in command-line arguments because they may appear in process listings or shell history.

## Workflow

1. Generate fresh P-256 private keys for Alice and Bob.
2. Each uses their own private key and the other's public key in a separate ECDH exchange.
3. Feed the resulting shared bytes through HKDF-SHA256 with the same 32-byte random salt and fixed demo context.
4. Encrypt UTF-8 text with Alice's derived key, a fresh 12-byte nonce, and AES-GCM using the demo context as authenticated additional data.
5. Bob derives his key independently and verifies/decrypts the ciphertext. Authentication failure raises InvalidTag; no unverified plaintext is returned.

ECDH is key agreement, not message encryption. The public key is not sufficient to decrypt a message. The old handwritten scalar-arithmetic code is not used by this implementation.

## Preserved reference material

`EllipticCurve` and `EllipticCurveOfDiffieHellman` are the original extensionless pseudocode files, retained unchanged as historical learning material. They are not executable Python modules. The original sketches use secp256k1 and AES-EAX; the new runnable example deliberately uses library-backed P-256, HKDF, and AES-GCM. It does not claim wire-format or API compatibility with those sketches.

## Scope and limitations

Both participants exist in one process. This is not a complete secure messaging protocol: public keys are not authenticated, so an untrusted exchange would be vulnerable to active substitution. There is no identity binding, certificate/signature validation, replay protection, key persistence, or network transport. Random nonces are adequate for this small demonstration; no high-volume nonce-lifecycle design is included. The cryptographic primitives are library-backed, but the demonstration itself has not undergone a security audit.

Tests check independent key derivation, Unicode/empty-message round trips, rejection of changed ciphertext, wrong keys/salt, curve and input validation, and CLI/import behavior. No real keys or user secrets are committed. This demonstrates cryptographic API use, not statistical modeling or ML.

## References

- [cryptography elliptic-curve API and ECDH](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ec/)
- [HKDF](https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/#hkdf)
- [AES-GCM authenticated encryption](https://cryptography.io/en/stable/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
