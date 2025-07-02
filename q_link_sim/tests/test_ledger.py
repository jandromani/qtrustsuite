import unittest
import os
import json
import jsonpickle
import datetime
import hashlib
from sqlalchemy.orm import sessionmaker
from q_link_sim.q_ledger.models import LedgerEvent, init_db
from q_link_sim.q_ledger.audit import initialize_audit_db, register_event, get_all_events, verify_ledger_integrity
from q_link_sim.q_ledger.utils import calculate_hash, get_timestamp

# Mock the blockchain send function to prevent actual network calls during tests
class MockBlockchain:
    def send_to_blockchain(self, entry_hash: str, metadata: dict) -> str:
        # Simulate a transaction hash
        return f"mock_tx_hash_{hashlib.sha256(entry_hash.encode()).hexdigest()[:10]}"

# Patch the import in audit.py
import q_link_sim.q_ledger.audit as audit_module
_original_send_to_blockchain = audit_module.send_to_blockchain
audit_module.send_to_blockchain = MockBlockchain().send_to_blockchain

class TestLedger(unittest.TestCase):

    def setUp(self):
        # Use an in-memory SQLite database for testing
        self.db_path = ':memory:'
        self.Session = init_db(self.db_path)
        initialize_audit_db(self.db_path) # Re-initialize the global Session in audit module

    def tearDown(self):
        # Clean up the in-memory database (not strictly necessary as it's in-memory, but good practice)
        # For file-based DBs, you'd delete the file here.
        pass

    def test_register_event_basic(self):
        session_id = "test-session-123"
        register_event(
            event_type="TEST_EVENT",
            session_id=session_id,
            origin_node="NodeA",
            dest_node="NodeB",
            key_length_bits=256,
            event_metadata={"test_key": "test_value"}
        )
        events = get_all_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["event_type"], "TEST_EVENT")
        self.assertEqual(event["session_id"], session_id)
        self.assertEqual(event["origin_node"], "NodeA")
        self.assertEqual(event["dest_node"], "NodeB")
        self.assertEqual(event["key_length_bits"], 256)
        self.assertIsNotNone(event["entry_hash"])
        self.assertIsInstance(event["metadata"], dict)
        self.assertEqual(event["metadata"]["test_key"], "test_value")

    def test_register_event_with_message_hash(self):
        session_id = "test-session-456"
        message_content = "This is a secret message."
        register_event(
            event_type="MESSAGE_SENT",
            session_id=session_id,
            message_content=message_content
        )
        events = get_all_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["event_type"], "MESSAGE_SENT")
        self.assertEqual(event["message_hash"], hashlib.sha256(message_content.encode('utf-8')).hexdigest())

    def test_register_event_blockchain_anchored(self):
        session_id = "test-session-789"
        # QKD_SUCCESS is a blockchain-anchored event type
        register_event(
            event_type="QKD_SUCCESS",
            session_id=session_id,
            origin_node="Alice",
            dest_node="Bob",
            key_length_bits=256
        )
        events = get_all_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["event_type"], "QKD_SUCCESS")
        self.assertIn("blockchain_tx_hash", event["metadata"])
        self.assertTrue(event["metadata"]["blockchain_tx_hash"].startswith("mock_tx_hash_"))

    def test_verify_ledger_integrity_success(self):
        session_id1 = "integrity-test-1"
        session_id2 = "integrity-test-2"
        register_event(event_type="EVENT_A", session_id=session_id1, event_metadata={"data": 1})
        register_event(event_type="EVENT_B", session_id=session_id2, event_metadata={"data": 2})

        all_events = get_all_events()
        self.assertTrue(verify_ledger_integrity(all_events))

    def test_verify_ledger_integrity_failure(self):
        session_id = "integrity-test-fail"
        register_event(event_type="EVENT_C", session_id=session_id, event_metadata={"data": 3})

        all_events = get_all_events()
        
        # Tamper with an event's data in the retrieved list (simulating external tampering)
        tampered_event = all_events[0]
        tampered_event["event_type"] = "TAMPERED_EVENT" # Change a field
        
        self.assertFalse(verify_ledger_integrity(all_events)) # Should detect the tamper

    def test_calculate_hash_consistency(self):
        data1 = {"a": 1, "b": "hello", "c": [1, 2]}
        data2 = {"b": "hello", "a": 1, "c": [1, 2]} # Same data, different order
        
        hash1 = calculate_hash(data1)
        hash2 = calculate_hash(data2)
        
        self.assertEqual(hash1, hash2) # Hashes should be identical due to sorting

        # Test with nested dicts and jsonpickled content
        nested_data = {"key": "value", "complex": jsonpickle.encode({"numpy_array": np.array([1,2,3]).tolist()})}
        hash_nested = calculate_hash(nested_data)
        self.assertIsInstance(hash_nested, str)
        self.assertEqual(len(hash_nested), 64) # SHA256 length

    def test_get_all_events_empty(self):
        # Re-initialize DB to ensure it's empty
        self.setUp() 
        events = get_all_events()
        self.assertEqual(len(events), 0)

# Restore original send_to_blockchain after tests
@unittest.skip("Skipping restoration of send_to_blockchain to avoid interference with other tests if run together.")
class RestoreBlockchainMock(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        audit_module.send_to_blockchain = _original_send_to_blockchain

if __name__ == '__main__':
    unittest.main()
