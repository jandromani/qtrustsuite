from flask import Blueprint, render_template, request, redirect, url_for, flash
import uuid
import logging
from q_commsec_api.crypto.cipher import SecureCipher
from q_commsec_api.crypto.key_manager import KeyManager
from q_commsec_api.crypto.session_store import SessionStoreError

logger = logging.getLogger(__name__)

def create_ui_blueprint(key_manager: KeyManager, secure_cipher: SecureCipher):
    """
    Creates and configures the Flask Blueprint for the web user interface.

    Args:
        key_manager (KeyManager): An instance of the KeyManager for key operations.
        secure_cipher (SecureCipher): An instance of the SecureCipher for encryption/decryption.

    Returns:
        Blueprint: The configured Flask Blueprint.
    """
    ui_bp = Blueprint('ui_bp', __name__, template_folder='../templates')

    @ui_bp.route('/', methods=['GET', 'POST'])
    def index():
        """
        Handles the main web interface for generating keys, encrypting, and decrypting.
        """
        session_id = request.form.get('session_id', '')
        message = request.form.get('message', '')
        ciphertext = request.form.get('ciphertext', '')
        result_ciphertext = None
        result_decrypted_message = None
        error_message = None

        if request.method == 'POST':
            action = request.form.get('action')
            client_ip = request.remote_addr # Get client IP for logging

            try:
                if action == 'generate_session':
                    symmetric_key = key_manager.generate_symmetric_key()
                    session_id = str(uuid.uuid4())
                    key_manager.store_session_key(session_id, symmetric_key)
                    flash(f"New session generated: {session_id}", 'success')
                    logger.info(f"[UI_SessionGeneration] OK - Session: {session_id}, IP: {client_ip}")
                
                elif action == 'encrypt':
                    if not session_id:
                        raise ValueError("Session ID is required for encryption.")
                    if not message:
                        raise ValueError("Message is required for encryption.")
                    
                    key = key_manager.get_session_key(session_id)
                    if not key:
                        raise ValueError("Invalid or expired Session ID. Please generate a new session.")
                    
                    result_ciphertext = secure_cipher.encrypt(message, key)
                    flash("Message encrypted successfully!", 'success')
                    ciphertext = result_ciphertext # Pre-fill ciphertext field for decryption
                    logger.info(f"[UI_MessageEncryption] OK - Session: {session_id}, IP: {client_ip}")

                elif action == 'decrypt':
                    if not session_id:
                        raise ValueError("Session ID is required for decryption.")
                    if not ciphertext:
                        raise ValueError("Ciphertext is required for decryption.")
                    
                    key = key_manager.get_session_key(session_id)
                    if not key:
                        raise ValueError("Invalid or expired Session ID. Please generate a new session.")
                    
                    result_decrypted_message = secure_cipher.decrypt(ciphertext, key)
                    flash("Message decrypted successfully!", 'success')
                    logger.info(f"[UI_MessageDecryption] OK - Session: {session_id}, IP: {client_ip}")

            except (ValueError, SessionStoreError) as e:
                error_message = str(e)
                flash(error_message, 'error')
                logger.warning(f"[UI_ActionError] ERROR - Action: {action}, Session: {session_id or 'N/A'}, IP: {client_ip}, Detail: {error_message}")
            except Exception as e:
                error_message = f"An unexpected error occurred: {e}"
                flash(error_message, 'error')
                logger.error(f"[UI_ActionException] EXCEPTION - Action: {action}, Session: {session_id or 'N/A'}, IP: {client_ip}, Error: {e}", exc_info=True)

        return render_template(
            'index.html',
            session_id=session_id,
            message=message,
            ciphertext=ciphertext,
            result_ciphertext=result_ciphertext,
            result_decrypted_message=result_decrypted_message,
            error_message=error_message
        )

    return ui_bp
