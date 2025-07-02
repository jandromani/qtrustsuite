import pytest
import unittest
import streamlit as st
from unittest.mock import MagicMock, patch
from streamlit.testing.v1 import AppTest
import numpy as np
import os
import sys
from q_link_sim.q_academy.educational_mode import EducationalMode

# Add parent directory to sys.path for module imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Mock the orchestrator and crypto_bridge for testing educational_mode in isolation
# This prevents actual DB/API calls during unit tests
class MockOrchestrator:
    def assign_key_pair(self, *args, **kwargs):
        # Simulate a successful key assignment
        return {
            "session_id": "mock_orchestrator_session_id",
            "key_type": "QKD",
            "key": os.urandom(32),
            "qkd_compatible_bits": np.random.randint(0, 2, 256).tobytes()
        }
    def validate_session(self, session_id):
        return {"session_id": session_id, "key": os.urandom(32)} # Always valid for mock

class MockCryptoBridge:
    def encrypt_message_with_session(self, session_id, plaintext):
        return f"encrypted({plaintext})"
    def decrypt_message_with_session(self, session_id, ciphertext):
        if ciphertext.startswith("encrypted(") and ciphertext.endswith(")"):
            return ciphertext[len("encrypted("):-1]
        return "decrypted(mock_error)"

# Patch the imports in the module under test
import q_link_sim.q_academy.educational_mode as edu_mode
import q_link_sim.integration.crypto_bridge as crypto_bridge_module
import q_link_sim.q_sync_bridge.orchestrator as orchestrator_module

# Store original functions to restore after tests
_original_get_orchestrator_instance = orchestrator_module.get_orchestrator_instance
_original_encrypt_message_with_session = crypto_bridge_module.encrypt_message_with_session
_original_decrypt_message_with_session = crypto_bridge_module.decrypt_message_with_session

def mock_get_orchestrator_instance():
    return MockOrchestrator()

def mock_encrypt_message_with_session(session_id, plaintext):
    return MockCryptoBridge().encrypt_message_with_session(session_id, plaintext)

def mock_decrypt_message_with_session(session_id, ciphertext):
    return MockCryptoBridge().decrypt_message_with_session(session_id, ciphertext)

class TestEducationalMode(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Apply mocks globally for these tests
        orchestrator_module.get_orchestrator_instance = mock_get_orchestrator_instance
        crypto_bridge_module.encrypt_message_with_session = mock_encrypt_message_with_session
        crypto_bridge_module.decrypt_message_with_session = mock_decrypt_message_with_session

    @classmethod
    def tearDownClass(cls):
        # Restore original functions
        orchestrator_module.get_orchestrator_instance = _original_get_orchestrator_instance
        crypto_bridge_module.encrypt_message_with_session = _original_encrypt_message_with_session
        crypto_bridge_module.decrypt_message_with_session = _original_decrypt_message_with_session

    def setUp(self):
        # Reset Streamlit session state for each test
        if 'edu_progress' in st.session_state:
            del st.session_state['edu_progress']
        if 'edu_session_completed' in st.session_state:
            del st.session_state['edu_session_completed']
        if 'last_completed_edu_session' in st.session_state:
            del st.session_state['last_completed_edu_session']

    def test_bb84_flow(self):
        # Simulate Streamlit app behavior
        # Initial state
        edu_mode.launch_educational_session("Protocolo BB84")
        self.assertEqual(st.session_state.edu_progress["topic"], "Protocolo BB84")
        self.assertEqual(st.session_state.edu_progress["step"], 0)

        # Step 0 -> 1: Generate Bits and Bases
        st.button("Generar Bits y Bases de Alice").click()
        edu_mode.launch_educational_session("Protocolo BB84") # Rerun app
        self.assertEqual(st.session_state.edu_progress["step"], 1)
        self.assertIsNotNone(st.session_state.edu_progress["alice_bits"])
        self.assertIsNotNone(st.session_state.edu_progress["alice_bases"])
        self.assertEqual(st.session_state.edu_progress["score"], 10)

        # Step 1 -> 2: Bob Chooses Bases and Measures
        st.button("Continuar a Comparacion de Bases").click()
        edu_mode.launch_educational_session("Protocolo BB84") # Rerun app
        self.assertEqual(st.session_state.edu_progress["step"], 2)
        self.assertIsNotNone(st.session_state.edu_progress["bob_bases"])
        self.assertIsNotNone(st.session_state.edu_progress["bob_results"])
        self.assertEqual(st.session_state.edu_progress["score"], 20)

        # Step 2 -> 3: Public Base Comparison and Key Derivation
        st.button("Finalizar BB84 y Derivar Clave").click()
        edu_mode.launch_educational_session("Protocolo BB84") # Rerun app
        self.assertEqual(st.session_state.edu_progress["step"], 3)
        self.assertIsNotNone(st.session_state.edu_progress["qkd_key_bits"])
        self.assertIsNotNone(st.session_state.edu_progress["derived_aes_key"])
        self.assertGreater(st.session_state.edu_progress["shared_key_length"], 0)
        self.assertEqual(st.session_state.edu_progress["score"], 40)
        self.assertTrue(st.session_state.edu_session_completed)
        self.assertEqual(st.session_state.last_completed_edu_session["topic"], "Protocolo BB84")

    def test_aes_encryption_flow(self):
        # Step 0 -> 1: Get QKD Key from Orchestrator
        edu_mode.launch_educational_session("Cifrado AES con clave QKD")
        st.button("Obtener Clave QKD y Registrar en Orquestador").click()
        edu_mode.launch_educational_session("Cifrado AES con clave QKD")
        self.assertEqual(st.session_state.edu_progress["step"], 1)
        self.assertIsNotNone(st.session_state.edu_progress["orchestrator_session_id"])
        self.assertEqual(st.session_state.edu_progress["score"], 20)

        # Step 1 -> 2: Encrypt Message
        test_message = "Hello Quantum World!"
        st.text_area("Introduce el mensaje a cifrar:", value=test_message, key="edu_encrypt_input")
        st.button("Cifrar Mensaje").click()
        edu_mode.launch_educational_session("Cifrado AES con clave QKD")
        self.assertEqual(st.session_state.edu_progress["step"], 2)
        self.assertEqual(st.session_state.edu_progress["message_original"], test_message)
        self.assertEqual(st.session_state.edu_progress["message_encrypted"], f"encrypted({test_message})")
        self.assertEqual(st.session_state.edu_progress["score"], 50) # 20 + 30

        # Step 2 -> 3: Decrypt Message
        st.button("Descifrar Mensaje").click()
        edu_mode.launch_educational_session("Cifrado AES con clave QKD")
        self.assertEqual(st.session_state.edu_progress["step"], 3)
        self.assertEqual(st.session_state.edu_progress["message_decrypted"], test_message)
        self.assertEqual(st.session_state.edu_progress["score"], 90) # 50 + 40
        self.assertTrue(st.session_state.edu_session_completed)
        self.assertEqual(st.session_state.last_completed_edu_session["topic"], "Cifrado AES con clave QKD")

    def test_blockchain_audit_flow(self):
        # Step 0 -> 1: Register Critical Event
        edu_mode.launch_educational_session("Auditoria en Blockchain")
        st.button("Registrar Evento en Ledger y Blockchain").click()
        edu_mode.launch_educational_session("Auditoria en Blockchain")
        self.assertEqual(st.session_state.edu_progress["step"], 1)
        self.assertIsNotNone(st.session_state.edu_progress["tx_hash"]) # Mock should provide a dummy tx_hash
        self.assertEqual(st.session_state.edu_progress["score"], 50) # Full score for successful mock
        self.assertTrue(st.session_state.edu_session_completed)
        self.assertEqual(st.session_state.last_completed_edu_session["topic"], "Auditoria en Blockchain")

# Mock the Streamlit functions
@pytest.fixture(autouse=True)
def mock_streamlit():
    with patch('streamlit.session_state', {}) as mock_session_state, \
         patch('streamlit.write') as mock_write, \
         patch('streamlit.header') as mock_header, \
         patch('streamlit.subheader') as mock_subheader, \
         patch('streamlit.markdown') as mock_markdown, \
         patch('streamlit.button') as mock_button, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.expander') as mock_expander, \
         patch('streamlit.pyplot') as mock_pyplot, \
         patch('streamlit.image') as mock_image, \
         patch('streamlit.info') as mock_info, \
         patch('streamlit.success') as mock_success, \
         patch('streamlit.error') as mock_error, \
         patch('streamlit.warning') as mock_warning, \
         patch('streamlit.empty') as mock_empty:
        
        # Mock columns to return a list of mocks
        mock_columns.return_value = [MagicMock(), MagicMock()]
        
        # Mock button to return True for the first call, then False
        # This simulates a button click for the first step
        button_calls = [True] + [False] * 100 # Enough False for subsequent calls
        mock_button.side_effect = lambda *args, **kwargs: button_calls.pop(0) if button_calls else False

        yield {
            'session_state': mock_session_state,
            'write': mock_write,
            'header': mock_header,
            'subheader': mock_subheader,
            'markdown': mock_markdown,
            'button': mock_button,
            'columns': mock_columns,
            'expander': mock_expander,
            'pyplot': mock_pyplot,
            'image': mock_image,
            'info': mock_info,
            'success': mock_success,
            'error': mock_error,
            'warning': mock_warning,
            'empty': mock_empty
        }

@pytest.fixture
def edu_mode(mock_streamlit):
    # Reset session state for each test
    mock_streamlit['session_state'].clear()
    mock_streamlit['session_state']['edu_step'] = 0
    mock_streamlit['session_state']['bb84_data'] = None
    mock_streamlit['session_state']['eavesdrop_enabled'] = False
    return EducationalMode()

def test_initial_state(edu_mode, mock_streamlit):
    edu_mode.display_bb84_explanation()
    assert mock_streamlit['header'].called
    assert mock_streamlit['markdown'].called
    assert mock_streamlit['button'].called
    assert mock_streamlit['session_state']['edu_step'] == 0

def test_next_step_advances(edu_mode, mock_streamlit):
    # Simulate initial display
    edu_mode.display_bb84_explanation()
    assert mock_streamlit['session_state']['edu_step'] == 0

    # Simulate button click for "Next Step"
    # The mock_button fixture is set up to return True once
    edu_mode.display_bb84_explanation() # Call again to process the "click"
    assert mock_streamlit['session_state']['edu_step'] == 1
    assert mock_streamlit['subheader'].called
    assert mock_streamlit['info'].called

def test_reset_button(edu_mode, mock_streamlit):
    # Advance a few steps
    edu_mode.display_bb84_explanation() # Step 0
    edu_mode.display_bb84_explanation() # Step 1
    edu_mode.display_bb84_explanation() # Step 2
    assert mock_streamlit['session_state']['edu_step'] == 2

    # Simulate reset button click (assuming it's the second button)
    mock_streamlit['button'].side_effect = [False, True] # First button (Next) is False, second (Reset) is True
    edu_mode.display_bb84_explanation()
    assert mock_streamlit['session_state']['edu_step'] == 0
    assert mock_streamlit['session_state']['bb84_data'] is None

def test_eavesdropping_toggle(edu_mode, mock_streamlit):
    # Ensure we are at a step where eavesdropping can be toggled (e.g., step 0 or 1)
    edu_mode.display_bb84_explanation() # Step 0
    assert mock_streamlit['session_state']['eavesdrop_enabled'] == False

    # Simulate toggling eavesdropping (assuming the toggle button is clicked)
    with patch('streamlit.checkbox', return_value=True) as mock_checkbox:
        edu_mode.display_bb84_explanation()
        assert mock_checkbox.called
        assert mock_streamlit['session_state']['eavesdrop_enabled'] == True

    # Toggle back
    with patch('streamlit.checkbox', return_value=False) as mock_checkbox:
        edu_mode.display_bb84_explanation()
        assert mock_checkbox.called
        assert mock_streamlit['session_state']['eavesdrop_enabled'] == False

def test_bb84_simulation_data_generation(edu_mode, mock_streamlit):
    # Advance to step where simulation data is generated (Step 1)
    edu_mode.display_bb84_explanation() # Step 0
    edu_mode.display_bb84_explanation() # Step 1
    
    assert mock_streamlit['session_state']['bb84_data'] is not None
    data = mock_streamlit['session_state']['bb84_data']
    assert 'alice_bits' in data
    assert 'alice_bases' in data
    assert 'encoded_photons' in data
    assert 'bob_bases' in data
    assert 'measured_bits' in data
    assert 'sifted_key_alice' in data
    assert 'sifted_key_bob' in data
    assert 'qber' in data
    assert 'derived_aes_key' in data

def test_bb84_steps_display_content(edu_mode, mock_streamlit):
    # Test content for a few steps
    edu_mode.display_bb84_explanation() # Step 0
    mock_streamlit['markdown'].assert_any_call(
        "The BB84 protocol is a groundbreaking method for quantum key distribution..."
    )

    edu_mode.display_bb84_explanation() # Step 1 (Alice generates bits and bases)
    mock_streamlit['subheader'].assert_any_call("Step 1: Alice Prepares Photons")
    mock_streamlit['info'].assert_any_call("Alice generates a random sequence of bits (0s and 1s) and a random sequence of polarization bases (rectilinear `+` or diagonal `x`).")
    mock_streamlit['pyplot'].assert_called() # Should show visualization

    edu_mode.display_bb84_explanation() # Step 2 (Alice encodes and sends)
    mock_streamlit['subheader'].assert_any_call("Step 2: Alice Encodes and Sends")
    mock_streamlit['info'].assert_any_call("Alice encodes each bit into a photon's polarization state according to her chosen basis. She then sends these photons to Bob.")
    mock_streamlit['pyplot'].assert_called() # Should show visualization

    # Test that Eve's data is displayed if eavesdropping is enabled
    mock_streamlit['session_state']['eavesdrop_enabled'] = True
    edu_mode.display_bb84_explanation() # Step 3 (Eve's interception)
    mock_streamlit['subheader'].assert_any_call("Step 3: Eve's Interception (if enabled)")
    mock_streamlit['warning'].assert_any_call("If Eve intercepts, she measures the photons in random bases, re-encodes them, and sends them to Bob. This introduces errors that Alice and Bob can detect.")
    mock_streamlit['pyplot'].assert_called() # Should show visualization for Eve

    mock_streamlit['session_state']['eavesdrop_enabled'] = False # Reset for next test

if __name__ == '__main__':
    # To run these tests, you might need to install `streamlit-testing`
    # pip install streamlit-testing
    unittest.main()
