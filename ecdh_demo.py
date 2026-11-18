"""In-memory ECDH + HKDF + AES-GCM learning demo; not a transport protocol."""
import argparse
import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CONTEXT = b'portfolio-ecdh-demo-v1'


def derive_key(private_key, peer_public_key, salt):
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
        raise ValueError('Expected an EC private key and peer public key')
    if not isinstance(private_key.curve, ec.SECP256R1) or not isinstance(peer_public_key.curve, ec.SECP256R1):
        raise ValueError('This demo supports P-256 keys only')
    if not isinstance(salt, bytes) or len(salt) != 32:
        raise ValueError('Salt must be 32 bytes shared by both participants')
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=CONTEXT).derive(shared_secret)


def encrypt(message, key):
    if not isinstance(message, str):
        raise ValueError('Message must be text')
    payload = message.encode('utf-8')
    if len(payload) > 1000000:
        raise ValueError('Demo message limit is 1000000 UTF-8 bytes')
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('Key must contain 32 bytes')
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload, CONTEXT)
    return nonce, ciphertext


def decrypt(packet, key):
    if not isinstance(packet, tuple) or len(packet) != 2:
        raise ValueError('Packet must be a (nonce, ciphertext) tuple')
    nonce, ciphertext = packet
    if not isinstance(nonce, bytes) or len(nonce) != 12 or not isinstance(ciphertext, bytes) or len(ciphertext) < 16:
        raise ValueError('Invalid nonce or ciphertext format')
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('Key must contain 32 bytes')
    # InvalidTag propagates; unverified plaintext is never returned.
    return AESGCM(key).decrypt(nonce, ciphertext, CONTEXT).decode('utf-8')


def run_demo(message='Hello from Alice — مرحبا'):
    alice = ec.generate_private_key(ec.SECP256R1())
    bob = ec.generate_private_key(ec.SECP256R1())
    salt = os.urandom(32)
    alice_key = derive_key(alice, bob.public_key(), salt)
    bob_key = derive_key(bob, alice.public_key(), salt)
    packet = encrypt(message, alice_key)
    recovered = decrypt(packet, bob_key)
    return {'curve': 'P-256', 'kdf': 'HKDF-SHA256', 'cipher': 'AES-256-GCM', 'derived_keys_match': alice_key == bob_key, 'round_trip_verified': recovered == message, 'plaintext_utf8_bytes': len(message.encode('utf-8')), 'ciphertext_and_tag_bytes': len(packet[1]), 'nonce_bytes': len(packet[0])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--message', default='Hello from Alice — مرحبا', help='Synthetic demonstration text; command arguments may be visible to the OS')
    args = parser.parse_args()
    try:
        print(json.dumps(run_demo(args.message), indent=2))
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
