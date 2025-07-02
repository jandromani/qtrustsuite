import os
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class KeyManager:
    """
    Manages the generation and derivation of cryptographic keys.
    """
    def __init__(self):
        logger.info("KeyManager initialized.")

    def generate_symmetric_key(self, key_size_bytes: int = 32) -> bytes:
        """
        Generates a random symmetric key of a specified size.
        Default is 32 bytes (256 bits) for AES-256.

        Args:
            key_size_bytes (int): The desired size of the key in bytes.

        Returns:
            bytes: The generated symmetric key.
        """
        key = os.urandom(key_size_bytes)
        logger.debug(f"Generated symmetric key of {key_size_bytes} bytes.")
        return key

    def derive_key_from_shared_secret(self, shared_secret: bytes, salt: bytes = None, iterations: int = 100000, key_length: int = 32) -> bytes:
        """
        Derives a strong cryptographic key from a shared secret using PBKDF2.

        Args:
            shared_secret (bytes): The shared secret (e.g., from QKD or KEM).
            salt (bytes, optional): A random salt. If None, a new one is generated.
            iterations (int): Number of iterations for PBKDF2. Higher is more secure.
            key_length (int): Desired length of the derived key in bytes.

        Returns:
            bytes: The derived key.
        """
        if salt is None:
            salt = os.urandom(16) # Generate a random salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        derived_key = kdf.derive(shared_secret)
        logger.debug(f"Derived key of {key_length} bytes from shared secret using PBKDF2.")
        return derived_key, salt # Return salt so it can be stored/shared if needed

# Singleton instance
key_manager = KeyManager()
