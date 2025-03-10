"""Security utilities for the MCP Network Manager."""

import os
import base64
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Prefix for encrypted passwords to identify them
ENCRYPTED_PREFIX = "encrypted:"

# Environment variable for the master key
MASTER_KEY_ENV = "MCP_NETWORK_MANAGER_KEY"

# File to store the salt
SALT_FILE = "mcp_salt.key"


def get_or_create_master_key() -> bytes:
    """Get the master key from the environment or create a new one.
    
    Returns:
        The master key as bytes.
    """
    # Check if the key exists in the environment
    key = os.environ.get(MASTER_KEY_ENV)
    
    if not key:
        # Generate a new key if not found
        key = Fernet.generate_key().decode()
        print(f"WARNING: No master key found in environment variable {MASTER_KEY_ENV}.")
        print(f"A new key has been generated: {key}")
        print(f"Please set this as an environment variable: export {MASTER_KEY_ENV}='{key}'")
        print(f"Or add it to your .env file: {MASTER_KEY_ENV}='{key}'")
        
    return key.encode() if isinstance(key, str) else key


def get_or_create_salt() -> bytes:
    """Get the salt from the salt file or create a new one.
    
    Returns:
        The salt as bytes.
    """
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    
    # Generate a new salt if not found
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    
    return salt


def derive_key(master_key: bytes, salt: Optional[bytes] = None) -> bytes:
    """Derive a key from the master key and salt.
    
    Args:
        master_key: The master key.
        salt: The salt to use for key derivation. If not provided, the default salt is used.
        
    Returns:
        The derived key.
    """
    if salt is None:
        salt = get_or_create_salt()
        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    return base64.urlsafe_b64encode(kdf.derive(master_key))


def encrypt_password(password: str) -> str:
    """Encrypt a password.
    
    Args:
        password: The password to encrypt.
        
    Returns:
        The encrypted password as a string.
    """
    if not password:
        return ""
        
    # Check if the password is already encrypted
    if password.startswith(ENCRYPTED_PREFIX):
        return password
        
    master_key = get_or_create_master_key()
    key = derive_key(master_key)
    
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    
    # Return the encrypted password with a prefix to identify it
    return f"{ENCRYPTED_PREFIX}{encrypted.decode()}"


def decrypt_password(encrypted_password: str) -> str:
    """Decrypt an encrypted password.
    
    Args:
        encrypted_password: The encrypted password.
        
    Returns:
        The decrypted password.
        
    Raises:
        ValueError: If the password is not encrypted or decryption fails.
    """
    if not encrypted_password:
        return ""
        
    # Check if the password is encrypted
    if not encrypted_password.startswith(ENCRYPTED_PREFIX):
        return encrypted_password
        
    # Remove the prefix
    encrypted_data = encrypted_password[len(ENCRYPTED_PREFIX):]
    
    master_key = get_or_create_master_key()
    key = derive_key(master_key)
    
    f = Fernet(key)
    
    try:
        decrypted = f.decrypt(encrypted_data.encode())
        return decrypted.decode()
    except Exception as e:
        raise ValueError(f"Failed to decrypt password: {e}")


def is_password_encrypted(password: str) -> bool:
    """Check if a password is already encrypted.
    
    Args:
        password: The password to check.
        
    Returns:
        True if the password is encrypted, False otherwise.
    """
    return password.startswith(ENCRYPTED_PREFIX) if password else False 