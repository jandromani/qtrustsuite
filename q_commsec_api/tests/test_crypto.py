import unittest
import os
import base64
import datetime
from q_commsec_api.crypto.key_manager import KeyManager
from q_commsec_api.crypto.session_store import SessionStore
from q_commsec_api.crypto.cipher import AESCipher, CipherError

class TestCrypto(unittest.TestCase):

    def setUp(self):
        self.key_manager = KeyManager()
        self.session_store = SessionStore()
        self.aes_cipher = AESCipher()
        self.session_store.clear_all_sessions() # Ensure a clean state for each test

    def test_generate_symmetric_key(self):
        key = self.key_manager.generate_symmetric_key()
        self.assertEqual(len(key), 32) # Default key size
        key_16 = self.key_manager.generate_symmetric_key(16)
        self.assertEqual(len(key_16), 16)

    def test_derive_key_from_shared_secret(self):
        shared_secret = os.urandom(64) # Example shared secret
        derived_key, salt = self.key_manager.derive_key_from_shared_secret(shared_secret)
        self.assertEqual(len(derived_key), 32)
        self.assertEqual(len(salt), 16)

        # Test with provided salt
        fixed_salt = os.urandom(16)
        derived_key_2, used_salt_2 = self.key_manager.derive_key_from_shared_secret(shared_secret, salt=fixed_salt)
        self.assertEqual(derived_key, derived_key_2) # Should be same if shared_secret and salt are same
        self.assertEqual(fixed_salt, used_salt_2)

    def test_session_store_create_and_get(self):
        key = self.key_manager.generate_symmetric_key()
        session_id = self.session_store.create_session(key, duration_minutes=1)
        
        session_data = self.session_store.get_session(session_id)
        self.assertIsNotNone(session_data)
        self.assertEqual(session_data["key"], key)
        self.assertIn("expires_at", session_data)
        self.assertIn("created_at", session_data)
        self.assertIsInstance(session_data["expires_at"], datetime.datetime)
        self.assertIsInstance(session_data["created_at"], datetime.datetime)

        # Test expired session
        expired_session_id = self.session_store.create_session(key, duration_minutes=-1) # Already expired
        self.assertIsNone(self.session_store.get_session(expired_session_id))

    def test_session_store_delete(self):
        key = self.key_manager.generate_symmetric_key()
        session_id = self.session_store.create_session(key)
        self.assertTrue(self.session_store.delete_session(session_id))
        self.assertIsNone(self.session_store.get_session(session_id))
        self.assertFalse(self.session_store.delete_session("non-existent-id"))

    def test_aes_encrypt_decrypt(self):
        key = self.key_manager.generate_symmetric_key(32) # AES-256 key
        plaintext = "This is a secret message for testing AES encryption."
        
        encrypted_text = self.aes_cipher.encrypt(key, plaintext)
        self.assertIsInstance(encrypted_text, str)
        self.assertNotEqual(plaintext, encrypted_text) # Should not be the same

        decrypted_text = self.aes_cipher.decrypt(key, encrypted_text)
        self.assertEqual(plaintext, decrypted_text)

    def test_aes_encrypt_decrypt_with_different_key(self):
        key1 = self.key_manager.generate_symmetric_key(32)
        key2 = self.key_manager.generate_symmetric_key(32) # Different key
        plaintext = "Another secret message."

        encrypted_text = self.aes_cipher.encrypt(key1, plaintext)
        
        with self.assertRaises(CipherError):
            self.aes_cipher.decrypt(key2, encrypted_text) # Should fail with wrong key

    def test_aes_invalid_key_size(self):
        invalid_key = os.urandom(16) # AES-128 key, but we expect 256
        plaintext = "Test message."
        with self.assertRaises(CipherError):
            self.aes_cipher.encrypt(invalid_key, plaintext)
        
        valid_key = self.key_manager.generate_symmetric_key(32)
        encrypted_text = self.aes_cipher.encrypt(valid_key, plaintext)
        with self.assertRaises(CipherError):
            self.aes_cipher.decrypt(invalid_key, encrypted_text)

    def test_aes_tampered_ciphertext(self):
        key = self.key_manager.generate_symmetric_key(32)
        plaintext = "Message to tamper."
        encrypted_text = self.aes_cipher.encrypt(key, plaintext)

        # Tamper with the ciphertext (e.g., flip a bit)
        decoded_bytes = base64.b64decode(encrypted_text)
        tampered_bytes = bytearray(decoded_bytes)
        # Change one byte in the ciphertext part (after IV, before tag)
        if len(tampered_bytes) > 20: # Ensure there's enough data to tamper
            tampered_bytes[15] = tampered_bytes[15] ^ 0x01 # Flip a bit in the ciphertext
        tampered_encrypted_text = base64.b64encode(tampered_bytes).decode('utf-8')

        with self.assertRaises(CipherError):
            self.aes_cipher.decrypt(key, tampered_encrypted_text) # GCM should detect tampering

    def test_get_all_active_sessions(self):
        key1 = self.key_manager.generate_symmetric_key()
        key2 = self.key_manager.generate_symmetric_key()
        
        session_id1 = self.session_store.create_session(key1, duration_minutes=5)
        session_id2 = self.session_store.create_session(key2, duration_minutes=10)
        expired_session_id = self.session_store.create_session(key1, duration_minutes=-1)

        active_sessions = self.session_store.get_all_active_sessions()
        self.assertEqual(len(active_sessions), 2)
        self.assertIn(session_id1, active_sessions)
        self.assertIn(session_id2, active_sessions)
        self.assertNotIn(expired_session_id, active_sessions) # Expired session should be cleaned up

if __name__ == '__main__':
    # Configure logging for tests
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    unittest.main()
