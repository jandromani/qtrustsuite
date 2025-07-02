from flask import Blueprint, request, jsonify
import logging
from q_commsec_api.crypto.key_manager import key_manager
from q_commsec_api.crypto.session_store import session_store
from q_commsec_api.crypto.cipher import aes_cipher, CipherError

logger = logging.getLogger(__name__)
commsec_bp = Blueprint('commsec_bp', __name__)

@commsec_bp.route('/generate_key', methods=['POST'])
def generate_key():
    """
    Generates a new symmetric key and creates a session for it.
    Expected JSON: {"key_size_bytes": 32, "duration_minutes": 60, "metadata": {}}
    """
    data = request.get_json()
    key_size_bytes = data.get('key_size_bytes', 32)
    duration_minutes = data.get('duration_minutes', 60)
    metadata = data.get('metadata', {})

    try:
        key = key_manager.generate_symmetric_key(key_size_bytes)
        session_id = session_store.create_session(key, duration_minutes, metadata)
        logger.info(f"Key generated and session '{session_id[:8]}...' created.")
        return jsonify({
            "session_id": session_id,
            "key_length_bytes": len(key),
            "message": "Key generated and session created successfully."
        }), 201
    except Exception as e:
        logger.error(f"Error generating key: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@commsec_bp.route('/derive_key', methods=['POST'])
def derive_key():
    """
    Derives a key from a shared secret using PBKDF2.
    Expected JSON: {"shared_secret": "base64_encoded_secret", "salt": "base64_encoded_salt", "iterations": 100000, "key_length": 32, "duration_minutes": 60, "metadata": {}}
    """
    data = request.get_json()
    shared_secret_b64 = data.get('shared_secret')
    salt_b64 = data.get('salt')
    iterations = data.get('iterations', 100000)
    key_length = data.get('key_length', 32)
    duration_minutes = data.get('duration_minutes', 60)
    metadata = data.get('metadata', {})

    if not shared_secret_b64:
        return jsonify({"error": "shared_secret is required"}), 400

    try:
        shared_secret = base64.b64decode(shared_secret_b64)
        salt = base64.b64decode(salt_b64) if salt_b64 else None

        derived_key, used_salt = key_manager.derive_key_from_shared_secret(shared_secret, salt, iterations, key_length)
        session_id = session_store.create_session(derived_key, duration_minutes, metadata)
        
        logger.info(f"Key derived and session '{session_id[:8]}...' created.")
        return jsonify({
            "session_id": session_id,
            "key_length_bytes": len(derived_key),
            "used_salt": base64.b64encode(used_salt).decode('utf-8'),
            "message": "Key derived and session created successfully."
        }), 201
    except Exception as e:
        logger.error(f"Error deriving key: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@commsec_bp.route('/encrypt', methods=['POST'])
def encrypt_message():
    """
    Encrypts a message using a key from an active session.
    Expected JSON: {"session_id": "uuid", "plaintext": "your message"}
    """
    data = request.get_json()
    session_id = data.get('session_id')
    plaintext = data.get('plaintext')

    if not session_id or not plaintext:
        return jsonify({"error": "session_id and plaintext are required"}), 400

    session_data = session_store.get_session(session_id)
    if not session_data:
        return jsonify({"error": "Invalid or expired session ID"}), 404

    try:
        key = session_data["key"]
        encrypted_text = aes_cipher.encrypt(key, plaintext)
        logger.info(f"Message encrypted for session '{session_id[:8]}...'.")
        return jsonify({"ciphertext": encrypted_text}), 200
    except CipherError as e:
        logger.error(f"Encryption failed for session '{session_id[:8]}...': {e}", exc_info=True)
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error during encryption for session '{session_id[:8]}...': {e}", exc_info=True)
        return jsonify({"error": "Internal server error during encryption"}), 500

@commsec_bp.route('/decrypt', methods=['POST'])
def decrypt_message():
    """
    Decrypts a message using a key from an active session.
    Expected JSON: {"session_id": "uuid", "ciphertext": "base64_encoded_ciphertext"}
    """
    data = request.get_json()
    session_id = data.get('session_id')
    ciphertext = data.get('ciphertext')

    if not session_id or not ciphertext:
        return jsonify({"error": "session_id and ciphertext are required"}), 400

    session_data = session_store.get_session(session_id)
    if not session_data:
        return jsonify({"error": "Invalid or expired session ID"}), 404

    try:
        key = session_data["key"]
        decrypted_text = aes_cipher.decrypt(key, ciphertext)
        logger.info(f"Message decrypted for session '{session_id[:8]}...'.")
        return jsonify({"plaintext": decrypted_text}), 200
    except CipherError as e:
        logger.error(f"Decryption failed for session '{session_id[:8]}...': {e}", exc_info=True)
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error during decryption for session '{session_id[:8]}...': {e}", exc_info=True)
        return jsonify({"error": "Internal server error during decryption"}), 500

@commsec_bp.route('/session_status/<session_id>', methods=['GET'])
def get_session_status(session_id):
    """
    Checks the status of a session.
    """
    session_data = session_store.get_session(session_id)
    if session_data:
        return jsonify({
            "session_id": session_id,
            "status": "active",
            "expires_at": session_data["expires_at"].isoformat(),
            "created_at": session_data["created_at"].isoformat(),
            "key_length_bytes": len(session_data["key"]),
            "metadata": session_data["metadata"]
        }), 200
    else:
        return jsonify({"session_id": session_id, "status": "inactive or expired"}), 404

@commsec_bp.route('/revoke_session', methods=['POST'])
def revoke_session():
    """
    Revokes (deletes) an active session.
    Expected JSON: {"session_id": "uuid"}
    """
    data = request.get_json()
    session_id = data.get('session_id')

    if not session_id:
        return jsonify({"error": "session_id is required"}), 400

    if session_store.delete_session(session_id):
        logger.info(f"Session '{session_id[:8]}...' explicitly revoked.")
        return jsonify({"message": f"Session {session_id} revoked successfully."}), 200
    else:
        return jsonify({"error": f"Session {session_id} not found or already inactive."}), 404

@commsec_bp.route('/active_sessions', methods=['GET'])
def get_active_sessions():
    """
    Retrieves a list of all active sessions (excluding key material).
    """
    active_sessions = session_store.get_all_active_sessions()
    
    # Prepare data for response, excluding sensitive key material
    response_data = []
    for session_id, data in active_sessions.items():
        response_data.append({
            "session_id": session_id,
            "expires_at": data["expires_at"].isoformat(),
            "created_at": data["created_at"].isoformat(),
            "key_length_bytes": len(data["key"]),
            "metadata": data["metadata"]
        })
    logger.debug(f"Returning {len(response_data)} active sessions (metadata only).")
    return jsonify(response_data), 200
