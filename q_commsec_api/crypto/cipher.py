import os
import base64
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

logger = logging.getLogger(__name__)

class CipherError(Exception):
    """Custom exception for cipher operations."""
    pass

class AESCipher:
    """
    Provides AES encryption and decryption functionalities.
    Uses AES-256 in GCM mode for authenticated encryption.
    """
    def __init__(self):
        logger.info("AESCipher initialized.")

    def encrypt(self, key: bytes, plaintext: str) -> str:
        """
        Encrypts plaintext using AES-256 GCM.

        Args:
            key (bytes): The 32-byte AES key.
            plaintext (str): The string to encrypt.

        Returns:
            str: Base64 encoded string of nonce + ciphertext + tag.

        Raises:
            CipherError: If encryption fails.
        """
        if len(key) != 32:
            raise CipherError("AES key must be 32 bytes for AES-256.")

        try:
            iv = os.urandom(12) # GCM recommended IV size is 12 bytes
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # Pad the plaintext to be a multiple of the block size (if not using GCM's stream-like nature)
            # For GCM, padding is not strictly necessary as it's a stream cipher,
            # but for consistency with block cipher modes, we can still use it.
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            tag = encryptor.tag

            # Combine IV, ciphertext, and tag for storage/transmission
            # Base64 encode the combined bytes
            combined_data = iv + ciphertext + tag
            return base64.b64encode(combined_data).decode('utf-8')
        except Exception as e:
            logger.error(f"AES encryption failed: {e}", exc_info=True)
            raise CipherError(f"Encryption failed: {e}")

    def decrypt(self, key: bytes, encrypted_text: str) -> str:
        """
        Decrypts AES-256 GCM encrypted text.

        Args:
            key (bytes): The 32-byte AES key.
            encrypted_text (str): Base64 encoded string of nonce + ciphertext + tag.

        Returns:
            str: The decrypted plaintext.

        Raises:
            CipherError: If decryption fails (e.g., authentication tag mismatch).
        """
        if len(key) != 32:
            raise CipherError("AES key must be 32 bytes for AES-256.")

        try:
            combined_data = base64.b64decode(encrypted_text)
            
            iv = combined_data[:12]
            ciphertext = combined_data[12:-16] # Tag is 16 bytes
            tag = combined_data[-16:]

            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Unpad the plaintext
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            return plaintext.decode('utf-8')
        except Exception as e:
            logger.error(f"AES decryption failed: {e}", exc_info=True)
            raise CipherError(f"Decryption failed: {e}. Possible key mismatch or tampering.")

# Singleton instance
aes_cipher = AESCipher()
