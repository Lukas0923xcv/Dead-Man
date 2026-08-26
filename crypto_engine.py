"""
Cryptographic Engine providing AES-256-GCM authenticated encryption and decryption
with Dual-Key Split (256-Bit standard, supports 4096-bit compatibility).
"""

import base64
import os
from typing import Dict, Optional, Tuple

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Default to 256-bit AES keys
DEFAULT_KEY_BITS = int(os.getenv("KEY_BITS", "256"))
HKDF_SALT = b"SecureVault-Salt-v1"
HKDF_INFO = b"SecureVault-AES256GCM-Derivation"


def generate_key_bytes(bits: int = DEFAULT_KEY_BITS) -> bytes:
    """Generate cryptographically secure random bytes for a given bit length."""
    byte_len = bits // 8
    return os.urandom(byte_len)


def generate_key(bits: int = DEFAULT_KEY_BITS) -> str:
    """Generate a random key returned as a Base64 string."""
    return base64.b64encode(generate_key_bytes(bits)).decode("utf-8")


def generate_split_keys(bits: int = DEFAULT_KEY_BITS) -> Tuple[str, str]:
    """
    Generate two independent 256-bit random keys (Key A and Key B).
    
    :param bits: Bit length (default: 256 = 32 bytes).
    :return: (key_a_base64, key_b_base64)
    """
    key_a = generate_key(bits)
    key_b = generate_key(bits)
    return key_a, key_b


def combine_keys(key_a_b64: str, key_b_b64: str) -> bytes:
    """
    Combine Key A and Key B via constant-time XOR secret sharing.
    For standard 256-bit keys (32 bytes), direct XOR produces the master AES key.
    For extended keys (> 32 bytes), HKDF-SHA512 derives the master AES key.
    """
    try:
        a_bytes = base64.b64decode(key_a_b64.strip())
        b_bytes = base64.b64decode(key_b_b64.strip())
    except Exception as e:
        raise ValueError(f"Invalid Base64 key format: {e}")

    if len(a_bytes) != len(b_bytes):
        raise ValueError(f"Key lengths do not match: Key A is {len(a_bytes)} bytes, Key B is {len(b_bytes)} bytes.")

    if len(a_bytes) < 32:
        raise ValueError(f"Key length must be at least 32 bytes (256 bits). Got {len(a_bytes)} bytes.")

    # 1. 2-of-2 Secret Sharing XOR
    combined_secret = bytes(a ^ b for a, b in zip(a_bytes, b_bytes))

    # 2. For 256-bit (32-byte) keys: use directly as AES master key
    if len(combined_secret) == 32:
        return combined_secret

    # For larger keys (> 32 bytes): use HKDF-SHA512
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    )
    return hkdf.derive(combined_secret)


def encrypt_split(plaintext: str, key_bits: int = DEFAULT_KEY_BITS) -> Dict[str, str]:
    """
    Encrypt plaintext using Dual-Key split AES-256-GCM.
    
    :param plaintext: The text to encrypt.
    :param key_bits: Bit length for Key A and Key B (default: 256).
    :return: Dictionary containing key_a, key_b, encrypted_text, algorithm, and key_bits.
    """
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("The 'cryptography' package is required for AES-256-GCM.")

    if plaintext is None:
        raise ValueError("Plaintext cannot be None.")

    key_a, key_b = generate_split_keys(bits=key_bits)
    master_aes_key = combine_keys(key_a, key_b)

    nonce = os.urandom(12)
    data = plaintext.encode("utf-8")

    aesgcm = AESGCM(master_aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, None)
    payload = nonce + ciphertext_with_tag
    encrypted_b64 = base64.b64encode(payload).decode("utf-8")

    return {
        "key_a": key_a,
        "key_b": key_b,
        "encrypted_text": encrypted_b64,
        "algorithm": f"AES-256-GCM ({key_bits}-Bit Split)",
        "key_bits": key_bits,
    }


def decrypt_split(encrypted_b64: str, key_a_b64: str, key_b_b64: str) -> str:
    """
    Decrypt an AES-256-GCM payload using Key A and Key B.
    """
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("The 'cryptography' package is required for AES-256-GCM.")

    master_aes_key = combine_keys(key_a_b64, key_b_b64)
    return _decrypt_with_key_bytes(encrypted_b64, master_aes_key)


def encrypt_text(plaintext: str, key_b64: Optional[str] = None) -> Dict[str, str]:
    """
    Single-key encryption helper.
    """
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("The 'cryptography' package is required for AES-256-GCM.")

    if plaintext is None:
        raise ValueError("Plaintext cannot be None.")

    if key_b64:
        try:
            key_bytes = base64.b64decode(key_b64)
        except Exception as e:
            raise ValueError(f"Invalid Base64 key: {e}")
        if len(key_bytes) > 32:
            hkdf = HKDF(algorithm=hashes.SHA512(), length=32, salt=HKDF_SALT, info=HKDF_INFO)
            key_bytes = hkdf.derive(key_bytes)
        elif len(key_bytes) != 32:
            raise ValueError(f"Key must be at least 32 bytes (256 bits). Got {len(key_bytes)} bytes.")
    else:
        key_bytes = generate_key_bytes(256)
        key_b64 = base64.b64encode(key_bytes).decode("utf-8")

    nonce = os.urandom(12)
    data = plaintext.encode("utf-8")

    aesgcm = AESGCM(key_bytes)
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, None)
    payload = nonce + ciphertext_with_tag
    encrypted_b64 = base64.b64encode(payload).decode("utf-8")

    return {
        "key": key_b64,
        "encrypted_text": encrypted_b64,
        "algorithm": "AES-256-GCM",
        "length": len(plaintext),
    }


def decrypt_text(encrypted_b64: str, key_b64: str) -> str:
    """
    Single-key decryption helper.
    """
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("The 'cryptography' package is required for AES-256-GCM.")

    try:
        key_bytes = base64.b64decode(key_b64)
    except Exception as e:
        raise ValueError(f"Invalid Base64 key: {e}")

    if len(key_bytes) > 32:
        hkdf = HKDF(algorithm=hashes.SHA512(), length=32, salt=HKDF_SALT, info=HKDF_INFO)
        key_bytes = hkdf.derive(key_bytes)
    elif len(key_bytes) != 32:
        raise ValueError("Key must be at least 32 bytes (256 bits).")

    return _decrypt_with_key_bytes(encrypted_b64, key_bytes)


def _decrypt_with_key_bytes(encrypted_b64: str, key_bytes: bytes) -> str:
    """Internal helper to decrypt AES-256-GCM with 32-byte key."""
    if not encrypted_b64:
        raise ValueError("Encrypted text payload cannot be empty.")

    try:
        payload = base64.b64decode(encrypted_b64.strip())
    except Exception as e:
        raise ValueError(f"Invalid Base64 ciphertext: {e}")

    if len(payload) < 28:
        raise ValueError("Ciphertext payload is too short for AES-256-GCM.")

    nonce = payload[:12]
    ciphertext_with_tag = payload[12:]

    aesgcm = AESGCM(key_bytes)
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception:
        raise ValueError("Decryption failed. Key is incorrect, tampered with, or corrupted.")

    return decrypted_bytes.decode("utf-8")
