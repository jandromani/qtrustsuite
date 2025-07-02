import pytest
import os
import datetime
from unittest.mock import MagicMock, patch
from q_link_sim.q_sync_bridge.bridge_scada import SCADABridge
from q_link_sim.q_cipher.qcipher import Q_Cipher
from q_link_sim.q_sync_bridge.orchestrator import QuantumOrchestrator # Import actual orchestrator for type hinting

# Mock the orchestrator instance
@pytest.fixture
def mock_orchestrator():
    orchestrator = MagicMock(spec=QuantumOrchestrator)
    # Configure mock_orchestrator.assign_key_pair
    orchestrator.assign_key_pair.return_value = {
        "session_id": "mock-session-123",
        "key_type": "QKD",
        "key": os.urandom(32), # Mock a 32-byte key
        "qkd_compatible_bits": None
    }
    # Configure mock_orchestrator.validate_session
    orchestrator.validate_session.return_value = {
        "session_id": "mock-session-123",
        "status": "active",
        "key": os.urandom(32),
        "key_type": "QKD",
        "expires_at": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        "origin": "mock-device",
        "destination": "mock-dest",
        "system_type": "SCADA",
        "priority_level": "high",
        "qkd_compatible_bits": None
    }
    return orchestrator

# Mock the register_event function from q_ledger.audit
@pytest.fixture(autouse=True)
def mock_register_event():
    with patch('q_link_sim.q_sync_bridge.bridge_scada.register_event') as mock_reg_event:
        yield mock_reg_event

# Mock the Q_Cipher class
@pytest.fixture(autouse=True)
def mock_q_cipher():
    with patch('q_link_sim.q_sync_bridge.bridge_scada.Q_Cipher') as mock_cipher_class:
        mock_instance = MagicMock(spec=Q_Cipher)
        mock_instance.encrypt.return_value = (b"ciphertext", b"nonce", b"tag")
        mock_instance.decrypt.return_value = "decrypted_plaintext"
        mock_cipher_class.return_value = mock_instance
        yield mock_cipher_class

@pytest.fixture
def scada_bridge(mock_orchestrator):
    return SCADABridge("test-device", mock_orchestrator)

def test_scada_bridge_initialization(scada_bridge):
    assert scada_bridge.device_id == "test-device"
    assert scada_bridge.active_session is None
    assert scada_bridge.q_cipher is None

def test_request_and_establish_session_success(scada_bridge, mock_orchestrator, mock_q_cipher, mock_register_event):
    success = scada_bridge.request_and_establish_session("dest-device")
    assert success is True
    mock_orchestrator.assign_key_pair.assert_called_once_with(
        origin="test-device", destination="dest-device", system_type="SCADA", priority_level="high"
    )
    assert scada_bridge.active_session is not None
    assert scada_bridge.q_cipher is not None
    mock_q_cipher.assert_called_once_with(mock_orchestrator.assign_key_pair.return_value["key"])
    mock_register_event.assert_called_once_with(
        event_type="SCADA_SESSION_ESTABLISHED",
        session_id="mock-session-123",
        origin_node="test-device",
        dest_node="dest-device",
        key_length_bits=256, # 32 bytes * 8 bits/byte
        event_metadata={"key_type": "QKD", "system_type": "SCADA"}
    )

def test_request_and_establish_session_failure(scada_bridge, mock_orchestrator, mock_register_event):
    mock_orchestrator.assign_key_pair.return_value = None # Simulate failure to get key
    success = scada_bridge.request_and_establish_session("dest-device")
    assert success is False
    assert scada_bridge.active_session is None
    assert scada_bridge.q_cipher is None
    mock_register_event.assert_not_called()

def test_send_secure_command_no_session(scada_bridge):
    command = "CLOSE_VALVE"
    result = scada_bridge.send_secure_command(command)
    assert result is None

def test_send_secure_command_success(scada_bridge, mock_orchestrator, mock_q_cipher, mock_register_event):
    scada_bridge.request_and_establish_session("dest-device") # Establish session first
    mock_register_event.reset_mock() # Reset mock call count from session establishment

    command = "OPEN_PUMP"
    ciphertext, nonce, tag = scada_bridge.send_secure_command(command)
    
    mock_q_cipher.return_value.encrypt.assert_called_once_with(command)
    assert ciphertext == b"ciphertext"
    assert nonce == b"nonce"
    assert tag == b"tag"
    mock_register_event.assert_called_once_with(
        event_type="SCADA_COMMAND_ENCRYPTED",
        session_id="mock-session-123",
        origin_node="test-device",
        message_content=command,
        event_metadata={"ciphertext_len": 10, "nonce_len": 5, "tag_len": 3} # Based on mock_q_cipher.encrypt return
    )

def test_receive_and_decrypt_response_no_session(scada_bridge):
    result = scada_bridge.receive_and_decrypt_response(b"cipher", b"nonce", b"tag")
    assert result is None

def test_receive_and_decrypt_response_success(scada_bridge, mock_orchestrator, mock_q_cipher, mock_register_event):
    scada_bridge.request_and_establish_session("dest-device") # Establish session first
    mock_register_event.reset_mock() # Reset mock call count

    ciphertext = b"response_cipher"
    nonce = b"response_nonce"
    tag = b"response_tag"
    
    decrypted_text = scada_bridge.receive_and_decrypt_response(ciphertext, nonce, tag)
    
    mock_q_cipher.return_value.decrypt.assert_called_once_with(ciphertext, nonce, tag)
    assert decrypted_text == "decrypted_plaintext"
    mock_register_event.assert_called_once_with(
        event_type="SCADA_RESPONSE_DECRYPTED",
        session_id="mock-session-123",
        dest_node="test-device",
        message_content="decrypted_plaintext",
        event_metadata={"ciphertext_len": len(ciphertext)}
    )

def test_receive_and_decrypt_response_failure(scada_bridge, mock_orchestrator, mock_q_cipher, mock_register_event):
    scada_bridge.request_and_establish_session("dest-device") # Establish session first
    mock_register_event.reset_mock() # Reset mock call count

    mock_q_cipher.return_value.decrypt.side_effect = ValueError("Decryption error") # Simulate decryption failure

    ciphertext = b"bad_cipher"
    nonce = b"bad_nonce"
    tag = b"bad_tag"
    
    decrypted_text = scada_bridge.receive_and_decrypt_response(ciphertext, nonce, tag)
    
    assert decrypted_text is None
    mock_register_event.assert_called_once_with(
        event_type="SCADA_DECRYPTION_FAILED",
        session_id="mock-session-123",
        dest_node="test-device",
        event_metadata={"error": "Decryption error", "ciphertext_len": len(ciphertext)}
    )

def test_validate_current_session_no_session(scada_bridge):
    is_valid = scada_bridge.validate_current_session()
    assert is_valid is False

def test_validate_current_session_valid(scada_bridge, mock_orchestrator):
    scada_bridge.request_and_establish_session("dest-device") # Establish session
    mock_orchestrator.validate_session.return_value = {"status": "active"} # Simulate valid
    
    is_valid = scada_bridge.validate_current_session()
    assert is_valid is True
    mock_orchestrator.validate_session.assert_called_once_with("mock-session-123")
    assert scada_bridge.active_session is not None # Session should still be active

def test_validate_current_session_invalid(scada_bridge, mock_orchestrator, mock_register_event):
    scada_bridge.request_and_establish_session("dest-device") # Establish session
    mock_orchestrator.validate_session.return_value = None # Simulate invalid/expired
    mock_register_event.reset_mock() # Reset mock call count

    is_valid = scada_bridge.validate_current_session()
    assert is_valid is False
    mock_orchestrator.validate_session.assert_called_once_with("mock-session-123")
    assert scada_bridge.active_session is None # Session should be cleared
    assert scada_bridge.q_cipher is None
    mock_register_event.assert_not_called() # Orchestrator's validate_session handles the event logging
