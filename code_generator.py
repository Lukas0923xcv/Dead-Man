"""
Cryptographically secure random code generator.
Provides functions to generate random strings/codes of configurable length and character sets.
"""

import secrets
import string
from typing import Optional

CHARSETS = {
    "alphanumeric": string.ascii_letters + string.digits,
    "digits": string.digits,
    "numeric": string.digits,
    "alpha": string.ascii_letters,
    "uppercase": string.ascii_uppercase + string.digits,
    "lowercase": string.ascii_lowercase + string.digits,
    "hex": "0123456789abcdef",
    "base64url": string.ascii_letters + string.digits + "-_",
}

DEFAULT_LENGTH = 16
DEFAULT_CHARSET = "alphanumeric"
MAX_LENGTH = 1024


def get_character_pool(charset_name_or_pool: str = DEFAULT_CHARSET) -> str:
    """
    Resolve a charset name to its character pool string, or return custom pool.
    """
    if not charset_name_or_pool:
        return CHARSETS[DEFAULT_CHARSET]
    
    charset_lower = charset_name_or_pool.lower()
    if charset_lower in CHARSETS:
        return CHARSETS[charset_lower]
    
    # Custom character pool provided directly
    return charset_name_or_pool


def generate_code(
    length: int = DEFAULT_LENGTH,
    charset: str = DEFAULT_CHARSET,
    custom_pool: Optional[str] = None,
) -> str:
    """
    Generate a cryptographically secure random code.

    :param length: Number of characters to generate (default: 16).
    :param charset: Preset charset name (alphanumeric, digits, alpha, uppercase, lowercase, hex, base64url).
    :param custom_pool: Direct custom characters to choose from (overrides charset).
    :return: A random string of the specified length.
    :raises ValueError: If length is invalid or character pool is empty.
    """
    if not isinstance(length, int) or length <= 0:
        raise ValueError("Length must be a positive integer greater than 0.")
    if length > MAX_LENGTH:
        raise ValueError(f"Length exceeds maximum allowable length ({MAX_LENGTH}).")

    pool = custom_pool if custom_pool is not None else get_character_pool(charset)
    if not pool:
        raise ValueError("Character pool cannot be empty.")

    return "".join(secrets.choice(pool) for _ in range(length))
