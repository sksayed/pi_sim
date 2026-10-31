"""Device-to-gateway hop.

The device holds the gateway ML-KEM public key and its own ML-DSA signing key.
Each message encapsulates a fresh shared secret, encrypts with AES-256-GCM, and
signs the ciphertext. The gateway decapsulates with a private key that stays on
the gateway and checks the signature against that device's pinned public key.
No master secret is used. Device-hop time is not part of Stage 2 re-encryption.
"""
