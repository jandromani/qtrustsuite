"""
Q-COMMSEC API – versión 0.2
------------------------------------------------
Endpoints:
• POST  /api/encrypt              – AES-GCM usando la clave de una sesión
• POST  /api/decrypt              – idem, descifrado
• GET   /api/sessions             – lista todas las sesiones activas del Orchestrator
• GET   /api/session/{id}         – detalles de una sesión concreta
• POST  /api/session/{id}/revoke  – revoca la sesión indicada
• POST  /api/hash/anchor          – ancla un hash (o texto) en la blockchain
• GET   /api/ping                 – salud del servicio
"""

from typing import List
import base64, logging

from fastapi import HTTPException, status
from q_commsec_api.crypto.key_manager import KeyManager
from q_commsec_api.crypto.cipher import AESCipher
import logging


from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from Crypto.Cipher import AES  # pip install pycryptodome

from q_link_sim.q_sync_bridge.orchestrator import get_orchestrator_instance
from q_link_sim.blockchain.polygon_bridge import send_to_blockchain

# Configuración del logging
log = logging.getLogger("q_commsec_api")
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())

app = FastAPI(title="Q-COMMSEC API")
orch = get_orchestrator_instance()

# ───────────────────────────
#  Modelos Pydantic
# ───────────────────────────
class EncryptIn(BaseModel):
    key: str  # Base64 del AES key de 32 bytes
    plaintext: str

class DecryptIn(BaseModel):
    session_id: str
    ciphertext: str  # Base64

class AnchorIn(BaseModel):
    data: str  # hash o texto libre

class SessionOut(BaseModel):
    session_id:     str
    origin:         str
    destination:    str
    system_type:    str
    key_type:       str
    priority_level: str
    status:         str
    expires_at:     str



def get_session_key_or_fail(session_id: str, orch: KeyManager) -> bytes:
    """
    Retrieves the session key or raises an HTTPException if the session is invalid or expired.
    """
    session = orch.get_session(session_id)
    if not session or session["status"] != "active":
        log.error(f"Session {session_id} is invalid or expired.")
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Session {session_id} is invalid or expired.")
    log.debug(f"Session {session_id} found. Returning key.")
    return session["symmetric_key"]

def encrypt_message(secure_cipher: AESCipher, session_id: str, message: str, orch: KeyManager) -> str:
    """
    Encrypts the message with the session key from Orchestrator.
    """
    key = get_session_key_or_fail(session_id, orch)
    ciphertext = secure_cipher.encrypt(message, key)
    log.info(f"Message encrypted successfully for session {session_id}")
    return ciphertext

def decrypt_message(secure_cipher: AESCipher, session_id: str, ciphertext: str, orch: KeyManager) -> str:
    """
    Decrypts the ciphertext with the session key from Orchestrator.
    """
    key = get_session_key_or_fail(session_id, orch)
    decrypted_message = secure_cipher.decrypt(ciphertext, key)
    log.info(f"Message decrypted successfully for session {session_id}")
    return decrypted_message


# ───────────────────────────
#  Helpers AES-GCM
# ───────────────────────────
def _get_key(session_id: str) -> bytes:
    log.debug(f"Fetching session {session_id} from Orchestrator.")
    s = orch.get_session(session_id)
    if not s or s["status"] != "active":
        log.error(f"Session {session_id} not found or inactive.")
        raise HTTPException(404, f"Session {session_id} not active")
    log.debug(f"Session {session_id} found. Returning key.")
    return s["symmetric_key"]

def _aes_gcm_encrypt(key: bytes, plaintext: str) -> str:
    log.debug(f"Encrypting plaintext: {plaintext[:32]}...")  # Log partial plaintext
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    blob = cipher.nonce + tag + ct
    ciphertext = base64.b64encode(blob).decode()
    log.debug(f"Encrypted ciphertext: {ciphertext[:32]}...")  # Log partial ciphertext
    return ciphertext

def _aes_gcm_decrypt(key: bytes, b64cipher: str) -> str:
    log.debug(f"Decrypting ciphertext: {b64cipher[:32]}...")  # Log partial ciphertext
    blob = base64.b64decode(b64cipher)
    nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ct, tag).decode()
        log.debug(f"Decrypted plaintext: {plaintext[:32]}...")  # Log partial plaintext
        return plaintext
    except ValueError as err:
        log.error(f"Decryption failed: {err}")
        raise HTTPException(400, "Auth tag mismatch – wrong key?") from err

# ───────────────────────────
#  Endpoints de cifrado
# ───────────────────────────
from fastapi import FastAPI, HTTPException
import logging

log = logging.getLogger("q_commsec_api")

@app.post("/api/encrypt")
def encrypt(inp: EncryptIn):
    try:
        key = base64.b64decode(inp.key)  # Decodifica la clave en base64
        cipher = AESCipher()
        encrypted_text = cipher.encrypt(key, inp.plaintext)
        return {"ciphertext": encrypted_text}
    except CipherError as e:
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")

@app.post("/api/decrypt")
def decrypt(inp: EncryptIn):
    try:
        key = base64.b64decode(inp.key)
        cipher = AESCipher()
        decrypted_text = cipher.decrypt(key, inp.plaintext)
        return {"plaintext": decrypted_text}
    except CipherError as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

# ───────────────────────────
#  Endpoints de sesiones (Orchestrator)
# ───────────────────────────
@app.get("/api/sessions", response_model=List[SessionOut])
def list_sessions():
    log.debug("Fetching active sessions from Orchestrator.")
    try:
        return orch.get_active_sessions()
    except Exception as e:
        log.error(f"Error fetching active sessions: {str(e)}")
        raise HTTPException(500, f"Failed to fetch active sessions: {str(e)}")

@app.get("/api/session/{session_id}", response_model=SessionOut)
def get_session(session_id: str):
    log.debug(f"Fetching session details for session_id: {session_id}")
    s = orch.get_session(session_id)
    if not s:
        log.error(f"Session {session_id} not found.")
        raise HTTPException(404, "Session not found")
    return s

@app.post("/api/session/{session_id}/revoke")
def revoke_session(session_id: str):
    log.debug(f"Revoking session {session_id}")
    if orch.revoke_session(session_id):
        log.debug(f"Session {session_id} revoked successfully.")
        return {"status": "revoked"}
    log.error(f"Session {session_id} not found or already inactive.")
    raise HTTPException(404, "Session not found or already inactive")

# ───────────────────────────
#  Anclaje en blockchain
# ───────────────────────────
@app.post("/api/hash/anchor")
def anchor_hash(inp: AnchorIn):
    log.debug(f"Anchoring hash: {inp.data}")
    tx = send_to_blockchain(inp.data)
    if not tx:
        log.error(f"Blockchain anchoring failed for data: {inp.data}")
        raise HTTPException(500, "Blockchain anchoring failed")
    log.debug(f"Blockchain tx hash: {tx}")
    return {"tx_hash": tx}

# ───────────────────────────
#  Ping
# ───────────────────────────
@app.get("/api/ping")
def ping():
    log.debug("Ping received, returning pong.")
    return {"pong": True}

# ───────────────────────────
#  Ruta raíz → redirección a Swagger
# ───────────────────────────
@app.get("/", include_in_schema=False)
def root():
    log.debug("Redirecting to Swagger docs.")
    return RedirectResponse(url="/docs")

# Ejecuta con:
#   uvicorn q_commsec_api.main:app --port 5000 --reload
