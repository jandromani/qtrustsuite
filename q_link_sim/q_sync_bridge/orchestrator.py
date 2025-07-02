import os
import uuid
import datetime
import logging
import numpy as np
from sqlalchemy import create_engine, Column, String, DateTime, Integer, LargeBinary
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import IntegrityError

# Import QKD simulation for key generation
from q_link_sim.simulator.qkd_bb84 import simulate_bb84
from q_link_sim.q_ledger.audit import register_event, initialize_audit_db

# Set up logger
logger = logging.getLogger(__name__)

# Base ORM class
Base = declarative_base()

class ActiveSession(Base):
    """
    SQLAlchemy ORM model for active sessions managed by the orchestrator.
    """
    __tablename__ = 'active_sessions'

    session_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    origin = Column(String, nullable=False)
    destination = Column(String, nullable=False)
    key_type = Column(String, nullable=False) # QKD, PQC, Fallback
    symmetric_key = Column(LargeBinary, nullable=True) # Store the actual symmetric key bytes
    qkd_compatible_bits = Column(LargeBinary, nullable=True) # Store numpy array as bytes for QKD
    expires_at = Column(DateTime, nullable=False)
    status = Column(String, nullable=False, default='active') # active, revoked, expired
    system_type = Column(String, nullable=False) # SCADA, ERP, API, etc.
    priority_level = Column(String, nullable=False) # high, medium, low
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))

    def __repr__(self):
        return (f"<ActiveSession(id={self.session_id[:8]}..., origin='{self.origin}', "
                f"dest='{self.destination}', key_type='{self.key_type}', status='{self.status}')>")

class QuantumOrchestrator:
    """
    Manages active sessions and key assignments based on system criticality.
    """
    def __init__(self, db_path: str = 'q_link_sim/data/q_sync_bridge/orchestrator.db'):
        self.db_path = db_path
        self._ensure_db_dir_exists()
        self.engine = create_engine(f'sqlite:///{self.db_path}')
        Base.metadata.create_all(self.engine)  # Create tables if they don't exist
        self.Session = sessionmaker(bind=self.engine)
        logger.info(f"[Orchestrator] Database initialized at {self.db_path}")

    def _ensure_db_dir_exists(self):
        """Ensure that the database directory exists."""
        db_dir = os.path.dirname(self.db_path)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
            logger.info(f"Created orchestrator database directory: {db_dir}")

    def _generate_qkd_key(self) -> tuple[bytes, bytes]:
        """Simulates QKD key generation and returns (derived_aes_key, compatible_key_bits_bytes)."""
        _, _, _, _, compatible_key_bits, derived_aes_key, _, _ = simulate_bb84(num_bits=256)
        compatible_key_bits_bytes = compatible_key_bits.tobytes()
        return derived_aes_key, compatible_key_bits_bytes

    def _generate_pqc_key(self) -> bytes:
        """Simulates PQC key generation (e.g., Kyber-like 32-byte key)."""
        return os.urandom(32)  # 32 bytes for AES-256

    def _generate_fallback_key(self) -> bytes:
        """Generates a fallback symmetric key (e.g., 16-byte AES-128)."""
        return os.urandom(16)  # 16 bytes for AES-128

    def assign_key_pair(self, origin: str, destination: str, system_type: str, priority_level: str,
                        key_bytes: bytes = None, qkd_compatible_bits: bytes = None) -> dict:
        """
        Handles the generation and storage of key pairs, including logging for auditing.
        """
        session = self.Session()
        new_session_id = str(uuid.uuid4())
        try:
            # Generate or get keys based on the session type
            if system_type == "SCADA" or priority_level == "high":
                key_type = "QKD"
                key_bytes, qkd_compatible_bits = self._generate_qkd_key()
            elif system_type == "ERP" or priority_level == "medium":
                key_type = "PQC"
                key_bytes = self._generate_pqc_key()
            else:
                key_type = "Fallback"
                key_bytes = self._generate_fallback_key()

            # Store in session DB
            new_session = ActiveSession(
                session_id=new_session_id,
                origin=origin,
                destination=destination,
                key_type=key_type,
                symmetric_key=key_bytes,
                qkd_compatible_bits=qkd_compatible_bits,
                expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
                status='active',
                system_type=system_type,
                priority_level=priority_level
            )
            session.add(new_session)
            session.commit()

            # Log event and return the result
            logger.info(f"Session {new_session_id[:8]}... created with key type {key_type}.")
            register_event(
                event_type="ORCH_SESSION_ASSIGNED",
                session_id=new_session_id,
                origin_node=origin,
                dest_node=destination,
                key_length_bits=len(key_bytes) * 8,
                event_metadata={"system_type": system_type, "priority_level": priority_level, "key_type": key_type}
            )

            return {
                "session_id": new_session_id,
                "key_type": key_type,
                "key": key_bytes
            }
        except IntegrityError:
            session.rollback()
            logger.error(f"Integrity error: Session ID {new_session_id} already exists.")
            raise
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating session for {system_type}-{origin} to {destination}: {e}")
            raise
        finally:
            session.close()


    def get_session(self, session_id: str) -> dict | None:
        """
        Retrieves a session by its ID from the active sessions table.

        Args:
            session_id (str): The ID of the session to retrieve.

        Returns:
            dict | None: A dictionary containing session details, or None if the session is not found.
        """
        session = self.Session()
        try:
            active_session = session.query(ActiveSession).filter_by(session_id=session_id).first()
            if active_session:
                compatible_bits_np = None
                if active_session.qkd_compatible_bits is not None:
                    compatible_bits_np = np.frombuffer(active_session.qkd_compatible_bits, dtype=np.uint8)
                return {
                    "session_id": active_session.session_id,
                    "origin": active_session.origin,
                    "destination": active_session.destination,
                    "key_type": active_session.key_type,
                    "key": active_session.symmetric_key,
                    "qkd_compatible_bits": compatible_bits_np,
                    "expires_at": active_session.expires_at,
                    "status": active_session.status,
                    "system_type": active_session.system_type,
                    "priority_level": active_session.priority_level
                }
            return None
        except Exception as e:
            logger.error(f"Error retrieving session {session_id}: {e}", exc_info=True)
            return None
        finally:
            session.close()

    def validate_session(self, session_id: str) -> dict | None:
        """
        Validates if a session is active and not expired.

        Args:
            session_id (str): The ID of the session to validate.

        Returns:
            dict | None: A dictionary containing session details and key if valid, else None.
        """
        session = self.Session()
        try:
            active_session = session.query(ActiveSession).filter_by(session_id=session_id, status='active').first()
            if active_session:
                # Convert stored datetime to timezone-aware UTC for comparison if it's naive
                expires_at_from_db = active_session.expires_at
                if expires_at_from_db.tzinfo is None:
                    expires_at_from_db = expires_at_from_db.replace(tzinfo=datetime.timezone.utc)

                if expires_at_from_db > datetime.datetime.now(datetime.timezone.utc):
                    logger.debug(f"Orchestrator: Session {session_id[:8]}... is valid.")
                    compatible_bits_np = None
                    if active_session.qkd_compatible_bits is not None:  # Check for None explicitly
                        compatible_bits_np = np.frombuffer(active_session.qkd_compatible_bits, dtype=np.uint8)
                    return {
                        "session_id": active_session.session_id,
                        "origin": active_session.origin,
                        "destination": active_session.destination,
                        "key_type": active_session.key_type,
                        "key": active_session.symmetric_key,
                        "qkd_compatible_bits": compatible_bits_np,
                        "expires_at": active_session.expires_at,
                        "status": active_session.status,
                        "system_type": active_session.system_type,
                        "priority_level": active_session.priority_level
                    }
                else:
                    active_session.status = 'expired'
                    session.commit()
                    logger.warning(f"Orchestrator: Session {session_id[:8]}... expired.")
                    register_event(
                        event_type="ORCH_SESSION_EXPIRED",
                        session_id=session_id,
                        event_metadata={"system_type": active_session.system_type, "key_type": active_session.key_type}
                    )
            logger.debug(f"Orchestrator: Session {session_id[:8]}... not found or not active/expired.")
            return None
        except Exception as e:
            logger.error(f"Error validating session {session_id}: {e}", exc_info=True)
            return None
        finally:
            session.close()

    def revoke_session(self, session_id: str) -> bool:
        """
        Revokes an active session, marking it as 'revoked'.

        Args:
            session_id (str): The ID of the session to revoke.

        Returns:
            bool: True if the session was found and revoked, False otherwise.
        """
        session = self.Session()
        try:
            active_session = session.query(ActiveSession).filter_by(session_id=session_id, status='active').first()
            if active_session:
                active_session.status = 'revoked'
                session.commit()
                logger.info(f"Orchestrator: Session {session_id[:8]}... revoked.")
                register_event(
                    event_type="ORCH_SESSION_REVOKED",
                    session_id=session_id,
                    event_metadata={"system_type": active_session.system_type, "key_type": active_session.key_type}
                )
                return True
            logger.warning(f"Orchestrator: Session {session_id[:8]}... not found or already revoked/expired.")
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Error revoking session {session_id}: {e}", exc_info=True)
            return False
        finally:
            session.close()

    def get_active_sessions(self) -> list[dict]:
        """
        Retrieves all active and non-expired sessions.
        Also updates expired sessions.

        Returns:
            list[dict]: A list of dictionaries, each representing an active session.
        """
        session = self.Session()
        try:
            # First, update any expired sessions
            now = datetime.datetime.now(datetime.timezone.utc)
            now_naive_utc = now.replace(tzinfo=None)  # Convert 'now' to naive UTC for comparison

            expired_sessions = session.query(ActiveSession).filter(
                ActiveSession.expires_at <= now_naive_utc,
                ActiveSession.status == 'active'
            ).all()
            for s in expired_sessions:
                s.status = 'expired'
                logger.warning(f"Orchestrator: Session {s.session_id[:8]}... automatically expired.")
                register_event(
                    event_type="ORCH_SESSION_AUTO_EXPIRED",
                    session_id=s.session_id,
                    event_metadata={"system_type": s.system_type, "key_type": s.key_type}
                )
            session.commit()

            # Then, retrieve all active sessions
            active_sessions = session.query(ActiveSession).filter(
                ActiveSession.status == 'active'
            ).all()

            session_list = []
            for s in active_sessions:
                compatible_bits_np = None
                if s.qkd_compatible_bits is not None:
                    compatible_bits_np = np.frombuffer(s.qkd_compatible_bits, dtype=np.uint8)
                session_list.append({
                    "session_id": s.session_id,
                    "origin": s.origin,
                    "destination": s.destination,
                    "key_type": s.key_type,
                    "symmetric_key": s.symmetric_key,  # Raw bytes
                    "qkd_compatible_bits": compatible_bits_np,  # Numpy array
                    "expires_at": s.expires_at,
                    "status": s.status,
                    "system_type": s.system_type,
                    "priority_level": s.priority_level,
                    "created_at": s.created_at
                })
            return session_list
        except Exception as e:
            logger.error(f"Error retrieving active sessions: {e}", exc_info=True)
            return []
        finally:
            session.close()

# Global orchestrator instance, initialized on import
orchestrator_instance = None

def get_orchestrator_instance():
    global orchestrator_instance
    if orchestrator_instance is None:
        orchestrator_instance = QuantumOrchestrator()
    return orchestrator_instance

if __name__ == "__main__":
    # This block runs when orchestrator.py is executed directly
    from q_link_sim.logging_config import setup_logging
    LOG_FILE_PATH_ORCH = os.path.join(os.path.dirname(__file__), '..', 'data', 'logs', 'orchestrator.log')
    setup_logging(log_file_path=LOG_FILE_PATH_ORCH, level=logging.INFO)

    # Initialize audit ledger
    LEDGER_DB_PATH_ORCH_STANDALONE = os.path.join(os.path.dirname(__file__), '..', 'data', 'q_ledger', 'ledger.db')
    initialize_audit_db(LEDGER_DB_PATH_ORCH_STANDALONE)

    orchestrator = get_orchestrator_instance()
    logger.info("[Orchestrator] Q-TRUST activo")

    # Example usage for standalone execution
    try:
        orchestrator.assign_key_pair("SCADA-A", "SCADA-B", "SCADA", "high")
        orchestrator.assign_key_pair("ERP-A", "ERP-B", "ERP", "medium")
        orchestrator.assign_key_pair("Web-Client", "API-Gateway", "API", "low")

        active_sessions = orchestrator.get_active_sessions()
        for s in active_sessions:
            print(f"ID: {s['session_id'][:8]}..., Type: {s['system_type']}, Key: {s['key_type']}, Status: {s['status']}")

        test_session_id = active_sessions[0]['session_id'] if active_sessions else None
        if test_session_id:
            validated_session = orchestrator.validate_session(test_session_id)
            if validated_session:
                print(f"Session {test_session_id[:8]}... is VALID. Key type: {validated_session['key_type']}")
            else:
                print(f"Session {test_session_id[:8]}... is INVALID or EXPIRED.")

            print(f"\nRevoking session {test_session_id[:8]}...")
            if orchestrator.revoke_session(test_session_id):
                print(f"Session {test_session_id[:8]}... REVOKED.")
            else:
                print(f"Failed to revoke session {test_session_id[:8]}...")

            validated_session_after_revoke = orchestrator.validate_session(test_session_id)
            if not validated_session_after_revoke:
                print(f"Session {test_session_id[:8]}... is now correctly INVALID after revocation.")

    except Exception as e:
        logger.error(f"Error in standalone orchestrator execution: {e}", exc_info=True)
