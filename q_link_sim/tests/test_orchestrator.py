import unittest
import os
import datetime
import numpy as np
from q_link_sim.q_sync_bridge.orchestrator import QuantumOrchestrator, ActiveSession, get_orchestrator_instance
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from q_link_sim.q_ledger.audit import initialize_audit_db, get_all_events # For checking audit logs

# Mock the QKD simulation to return consistent values for testing
class MockBB84:
    def simulate_bb84(self, num_bits: int = 256):
        compatible_key_bits = np.array([1, 0, 1, 1, 0, 1, 0, 0] * (num_bits // 8)) # Consistent pattern
        derived_aes_key = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10' * 2 # 32 bytes
        return (None, None, None, None, compatible_key_bits, derived_aes_key, num_bits, len(compatible_key_bits))

# Patch the import in orchestrator.py
import q_link_sim.q_sync_bridge.orchestrator as orchestrator_module
orchestrator_module.simulate_bb84 = MockBB84().simulate_bb84

# Mock the blockchain send function in audit.py to prevent actual network calls
import q_link_sim.q_ledger.audit as audit_module
class MockBlockchain:
    def send_to_blockchain(self, entry_hash: str, metadata: dict) -> str:
        return f"mock_tx_hash_{entry_hash[:10]}"
_original_send_to_blockchain = audit_module.send_to_blockchain
audit_module.send_to_blockchain = MockBlockchain().send_to_blockchain


class TestQuantumOrchestrator(unittest.TestCase):

    def setUp(self):
        # Use an in-memory SQLite database for testing
        self.db_path = ':memory:'
        self.orchestrator = QuantumOrchestrator(db_path=self.db_path)
        
        # Ensure audit DB is also initialized for event logging
        self.audit_db_path = ':memory:'
        initialize_audit_db(self.audit_db_path)

        # Clear any existing sessions in the in-memory DB
        session = self.orchestrator.Session()
        session.query(ActiveSession).delete()
        session.commit()
        session.close()

    def tearDown(self):
        # Restore original functions after tests
        orchestrator_module.simulate_bb84 = MockBB84().simulate_bb84 # Ensure it's reset
        audit_module.send_to_blockchain = _original_send_to_blockchain

    def test_assign_key_pair_qkd(self):
        result = self.orchestrator.assign_key_pair("NodeA", "NodeB", "SCADA", "high")
        self.assertIsNotNone(result["session_id"])
        self.assertEqual(result["key_type"], "QKD")
        self.assertEqual(len(result["key"]), 32) # AES-256 key
        self.assertIsInstance(result["qkd_compatible_bits"], np.ndarray)
        self.assertGreater(len(result["qkd_compatible_bits"]), 0)

        session = self.orchestrator.Session()
        stored_session = session.query(ActiveSession).filter_by(session_id=result["session_id"]).first()
        self.assertIsNotNone(stored_session)
        self.assertEqual(stored_session.key_type, "QKD")
        self.assertEqual(stored_session.origin, "NodeA")
        self.assertEqual(stored_session.destination, "NodeB")
        self.assertEqual(stored_session.system_type, "SCADA")
        self.assertEqual(stored_session.priority_level, "high")
        self.assertEqual(stored_session.status, "active")
        self.assertIsNotNone(stored_session.qkd_compatible_bits)
        session.close()

        # Check audit log
        audit_events = get_all_events()
        self.assertTrue(any(e['event_type'] == "ORCH_SESSION_ASSIGNED" and e['session_id'] == result["session_id"] for e in audit_events))

    def test_assign_key_pair_pqc(self):
        result = self.orchestrator.assign_key_pair("ERP-Server", "Client", "ERP", "medium")
        self.assertIsNotNone(result["session_id"])
        self.assertEqual(result["key_type"], "PQC")
        self.assertEqual(len(result["key"]), 32) # PQC simulated as 32 bytes
        self.assertIsNone(result["qkd_compatible_bits"])

        session = self.orchestrator.Session()
        stored_session = session.query(ActiveSession).filter_by(session_id=result["session_id"]).first()
        self.assertIsNotNone(stored_session)
        self.assertEqual(stored_session.key_type, "PQC")
        session.close()

    def test_assign_key_pair_fallback(self):
        result = self.orchestrator.assign_key_pair("Web", "API", "API", "low")
        self.assertIsNotNone(result["session_id"])
        self.assertEqual(result["key_type"], "Fallback")
        self.assertEqual(len(result["key"]), 16) # Fallback simulated as 16 bytes
        self.assertIsNone(result["qkd_compatible_bits"])

        session = self.orchestrator.Session()
        stored_session = session.query(ActiveSession).filter_by(session_id=result["session_id"]).first()
        self.assertIsNotNone(stored_session)
        self.assertEqual(stored_session.key_type, "Fallback")
        session.close()

    def test_assign_key_pair_with_pregenerated_key(self):
        pre_gen_key = os.urandom(32)
        pre_gen_qkd_bits = np.array([0,1,0,1]).tobytes()
        result = self.orchestrator.assign_key_pair("Custom", "Target", "CustomType", "high",
                                                    key_bytes=pre_gen_key, qkd_compatible_bits=pre_gen_qkd_bits)
        self.assertEqual(result["key"], pre_gen_key)
        self.assertEqual(result["key_type"], "QKD") # High priority defaults to QKD
        self.assertTrue(np.array_equal(result["qkd_compatible_bits"], np.frombuffer(pre_gen_qkd_bits, dtype=np.uint8)))

    def test_validate_session_active(self):
        result = self.orchestrator.assign_key_pair("A", "B", "SCADA", "high")
        validated = self.orchestrator.validate_session(result["session_id"])
        self.assertIsNotNone(validated)
        self.assertEqual(validated["session_id"], result["session_id"])
        self.assertEqual(validated["status"], "active")

    def test_validate_session_expired(self):
        # Assign a session that expires immediately
        session = self.orchestrator.Session()
        new_session = ActiveSession(
            session_id="expired-test",
            origin="X", destination="Y", key_type="Fallback", symmetric_key=os.urandom(16),
            expires_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1),
            system_type="Test", priority_level="low"
        )
        session.add(new_session)
        session.commit()
        session.close()

        validated = self.orchestrator.validate_session("expired-test")
        self.assertIsNone(validated) # Should be None because it's expired

        # Check if status was updated in DB
        session = self.orchestrator.Session()
        stored_session = session.query(ActiveSession).filter_by(session_id="expired-test").first()
        self.assertEqual(stored_session.status, "expired")
        session.close()

        # Check audit log for expiration
        audit_events = get_all_events()
        self.assertTrue(any(e['event_type'] == "ORCH_SESSION_EXPIRED" and e['session_id'] == "expired-test" for e in audit_events))


    def test_validate_session_non_existent(self):
        validated = self.orchestrator.validate_session("non-existent-id")
        self.assertIsNone(validated)

    def test_revoke_session(self):
        result = self.orchestrator.assign_key_pair("A", "B", "SCADA", "high")
        self.assertTrue(self.orchestrator.revoke_session(result["session_id"]))

        validated = self.orchestrator.validate_session(result["session_id"])
        self.assertIsNone(validated) # Should no longer be active

        session = self.orchestrator.Session()
        stored_session = session.query(ActiveSession).filter_by(session_id=result["session_id"]).first()
        self.assertEqual(stored_session.status, "revoked")
        session.close()

        # Check audit log for revocation
        audit_events = get_all_events()
        self.assertTrue(any(e['event_type'] == "ORCH_SESSION_REVOKED" and e['session_id'] == result["session_id"] for e in audit_events))

    def test_revoke_session_non_existent(self):
        self.assertFalse(self.orchestrator.revoke_session("non-existent-id"))

    def test_get_active_sessions(self):
        self.orchestrator.assign_key_pair("A1", "B1", "SCADA", "high")
        self.orchestrator.assign_key_pair("A2", "B2", "ERP", "medium")
        
        # Add an expired session
        session = self.orchestrator.Session()
        new_session = ActiveSession(
            session_id="temp-expired",
            origin="X", destination="Y", key_type="Fallback", symmetric_key=os.urandom(16),
            expires_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1),
            system_type="Test", priority_level="low"
        )
        session.add(new_session)
        session.commit()
        session.close()

        active_sessions = self.orchestrator.get_active_sessions()
        self.assertEqual(len(active_sessions), 2) # Only 2 active, 1 expired should be filtered/updated

        # Verify the expired session is now marked as expired in DB
        session = self.orchestrator.Session()
        stored_expired_session = session.query(ActiveSession).filter_by(session_id="temp-expired").first()
        self.assertEqual(stored_expired_session.status, "expired")
        session.close()

        # Check audit log for auto-expiration
        audit_events = get_all_events()
        self.assertTrue(any(e['event_type'] == "ORCH_SESSION_AUTO_EXPIRED" and e['session_id'] == "temp-expired" for e in audit_events))

    def test_get_orchestrator_instance_singleton(self):
        instance1 = get_orchestrator_instance()
        instance2 = get_orchestrator_instance()
        self.assertIs(instance1, instance2) # Should be the same instance

if __name__ == '__main__':
    unittest.main()
