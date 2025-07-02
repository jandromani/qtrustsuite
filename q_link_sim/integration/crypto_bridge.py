import requests
import base64
import logging
import numpy as np
import os

logger = logging.getLogger(__name__)

# URL of the Q-COMMSEC API (Flask backend)
QCOMMSEC_API_URL = os.getenv("QCOMMSEC_API_URL", "http://127.0.0.1:5000/api")

class CryptoBridgeError(Exception):
    """Custom exception for errors in the crypto bridge."""
    pass

def _get_session_id_from_orchestrator(origin: str, destination: str, system_type: str, priority_level: str) -> dict:
    """
    Requests a session ID and key details from the Q-TRUST Orchestrator.
    This is a placeholder for direct integration with the orchestrator.
    In a real system, this would involve a secure API call.
    """
    # For now, we'll simulate this by calling the orchestrator directly if it's running in the same process
    # or by assuming a pre-existing session.
    # This function is primarily for conceptual flow, as the Streamlit app directly uses the orchestrator instance.
    logger.warning("'_get_session_id_from_orchestrator' is a placeholder. Direct orchestrator calls are used in app.py.")
    return {
        "session_id": "simulated_orchestrator_session",
        "key_type": "QKD",
        "key": os.urandom(32), # Simulated 32-byte key
        "qkd_compatible_bits": np.random.randint(0, 2, 256) # Simulated compatible bits
    }

def encrypt_with_bb84_key(plaintext: str, compatible_key_bits: np.ndarray) -> str:
    """
    Encrypts a plaintext message using a key derived from BB84 compatible bits
    via the Q-COMMSEC API.

    Args:
        plaintext (str): The message to encrypt.
        compatible_key_bits (np.ndarray): The numpy array of compatible bits from BB84.

    Returns:
        str: The base64 encoded ciphertext.

    Raises:
        CryptoBridgeError: If encryption fails or API is unreachable.
    """
    if compatible_key_bits.size == 0:
        raise CryptoBridgeError("Cannot encrypt: No compatible key bits available from QKD.")

    # Convert compatible_key_bits to a byte string for key derivation
    # This should match the derivation logic in the Q-COMMSEC API's key_manager if used there.
    # For now, we'll just pass the raw bits and let the API handle derivation if needed,
    # or assume the API expects a pre-derived key.
    # For simplicity, let's assume the API expects a 32-byte key.
    # We'll hash the compatible bits to get a consistent 32-byte key.
    bit_string = ''.join(str(b) for b in compatible_key_bits)
    padded_bit_string = bit_string + '0' * ((8 - len(bit_string) % 8) % 8)
    derived_key_bytes = int(padded_bit_string, 2).to_bytes(len(padded_bit_string) // 8, byteorder='big')
    
    # Ensure the key is 32 bytes (AES-256)
    if len(derived_key_bytes) != 32:
        derived_key_bytes = hashlib.sha256(derived_key_bytes).digest()
    
    # First, create a session in the Q-COMMSEC API with this derived key
    try:
        key_b64 = base64.b64encode(derived_key_bytes).decode('utf-8')
        
        # Use the /derive_key endpoint if the API handles PBKDF2, otherwise /generate_key
        # For simplicity, let's use /generate_key and pass the key directly (conceptually)
        # In a real system, the key would be securely exchanged or derived on both ends.
        
        # Simulate session creation with the derived key
        # In a real scenario, the orchestrator would provide a session ID and the key
        # would be used by the crypto bridge.
        
        # For this simulation, we'll directly call the API's encrypt endpoint
        # and assume a session is managed or the key is passed securely.
        # The app.py directly uses the derived_aes_key from BB84 simulation.
        # So, this function will just use the key provided by the app.
        
        # The `app.py` already has the `shared_key_bytes` (derived AES key).
        # We need to create a session in the Q-COMMSEC API using this key.
        
        # This part needs to be handled by the Streamlit app, which calls the orchestrator
        # and then uses the session_id from the orchestrator.
        # This `encrypt_with_bb84_key` function should receive a session_id from the orchestrator.
        
        # For now, let's assume a session_id is passed or created implicitly.
        # This is a conceptual bridge. The actual key is managed by the orchestrator.
        
        # Let's make a direct call to the Q-COMMSEC API's /encrypt endpoint
        # For this to work, the Q-COMMSEC API needs to have a session with this key.
        # The Streamlit app will create the session via the orchestrator, and then pass the session_id here.
        
        # This function needs a session_id to work with the Q-COMMSEC API.
        # Let's modify it to accept session_id.
        raise NotImplementedError("This function needs to be refactored to accept a session_id from the orchestrator.")

    except requests.exceptions.ConnectionError as e:
        logger.error(f"Could not connect to Q-COMMSEC API at {QCOMMSEC_API_URL}: {e}")
        raise CryptoBridgeError(f"Failed to connect to Q-COMMSEC API: {e}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during encryption API call: {e}")
        raise CryptoBridgeError(f"Encryption API call failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in encrypt_with_bb84_key: {e}", exc_info=True)
        raise CryptoBridgeError(f"Encryption failed due to unexpected error: {e}")

def decrypt_with_bb84_key(ciphertext: str, compatible_key_bits: np.ndarray) -> str:
    """
    Decrypts a ciphertext message using a key derived from BB84 compatible bits
    via the Q-COMMSEC API.

    Args:
        ciphertext (str): The base64 encoded ciphertext.
        compatible_key_bits (np.ndarray): The numpy array of compatible bits from BB84.

    Returns:
        str: The decrypted plaintext.

    Raises:
        CryptoBridgeError: If decryption fails or API is unreachable.
    """
    if compatible_key_bits.size == 0:
        raise CryptoBridgeError("Cannot decrypt: No compatible key bits available from QKD.")

    # Similar to encryption, this function needs a session_id.
    raise NotImplementedError("This function needs to be refactored to accept a session_id from the orchestrator.")

# --- Refactored functions to use a session_id ---
# These functions will be called by app.py after it gets a session_id from the orchestrator.

def encrypt_message_with_session(session_id: str, plaintext: str) -> str:
    """
    Encrypts a plaintext message using a key associated with the given session_id
    via the Q-COMMSEC API.

    Args:
        session_id (str): The ID of the active session.
        plaintext (str): The message to encrypt.

    Returns:
        str: The base64 encoded ciphertext.

    Raises:
        CryptoBridgeError: If encryption fails or API is unreachable.
    """
    try:
        response = requests.post(f"{QCOMMSEC_API_URL}/encrypt", json={
            "session_id": session_id,
            "plaintext": plaintext
        })
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        result = response.json()
        if "ciphertext" not in result:
            raise CryptoBridgeError(f"API response missing ciphertext: {result}")
        logger.info(f"Message encrypted via Q-COMMSEC API for session {session_id[:8]}...")
        return result["ciphertext"]
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Could not connect to Q-COMMSEC API at {QCOMMSEC_API_URL}: {e}")
        raise CryptoBridgeError(f"Failed to connect to Q-COMMSEC API: {e}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during encryption API call for session {session_id[:8]}...: {e}")
        if response and response.status_code == 404:
            raise CryptoBridgeError(f"Session {session_id[:8]}... not found or expired on API side.")
        raise CryptoBridgeError(f"Encryption API call failed: {e}. Response: {response.text if response else 'N/A'}")
    except Exception as e:
        logger.error(f"Unexpected error in encrypt_message_with_session for session {session_id[:8]}...: {e}", exc_info=True)
        raise CryptoBridgeError(f"Encryption failed due to unexpected error: {e}")

def decrypt_message_with_session(session_id: str, ciphertext: str) -> str:
    """
    Decrypts a ciphertext message using a key associated with the given session_id
    via the Q-COMMSEC API.

    Args:
        session_id (str): The ID of the active session.
        ciphertext (str): The base64 encoded ciphertext.

    Returns:
        str: The decrypted plaintext.

    Raises:
        CryptoBridgeError: If decryption fails or API is unreachable.
    """
    try:
        response = requests.post(f"{QCOMMSEC_API_URL}/decrypt", json={
            "session_id": session_id,
            "ciphertext": ciphertext
        })
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        result = response.json()
        if "plaintext" not in result:
            raise CryptoBridgeError(f"API response missing plaintext: {result}")
        logger.info(f"Message decrypted via Q-COMMSEC API for session {session_id[:8]}...")
        return result["plaintext"]
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Could not connect to Q-COMMSEC API at {QCOMMSEC_API_URL}: {e}")
        raise CryptoBridgeError(f"Failed to connect to Q-COMMSEC API: {e}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during decryption API call for session {session_id[:8]}...: {e}")
        if response and response.status_code == 404:
            raise CryptoBridgeError(f"Session {session_id[:8]}... not found or expired on API side.")
        raise CryptoBridgeError(f"Decryption API call failed: {e}. Response: {response.text if response else 'N/A'}")
    except Exception as e:
        logger.error(f"Unexpected error in decrypt_message_with_session for session {session_id[:8]}...: {e}", exc_info=True)
        raise CryptoBridgeError(f"Decryption failed due to unexpected error: {e}")
