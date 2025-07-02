import uuid
import datetime
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class SessionStore:
    """
    Manages active cryptographic sessions, storing keys and metadata.
    In a real application, this would be backed by a secure, persistent store.
    """
    _instance = None
    _sessions: Dict[str, Dict[str, Any]] = {} # session_id -> {key, expires_at, metadata}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SessionStore, cls).__new__(cls)
            logger.info("SessionStore initialized.")
        return cls._instance

    def create_session(self, key: bytes, duration_minutes: int = 60, metadata: Dict[str, Any] = None) -> str:
        """
        Creates a new session and stores the key with an expiration time.

        Args:
            key (bytes): The symmetric key for the session.
            duration_minutes (int): How long the session should be active in minutes.
            metadata (Dict[str, Any], optional): Additional metadata for the session.

        Returns:
            str: The unique session ID.
        """
        session_id = str(uuid.uuid4())
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=duration_minutes)
        
        session_data = {
            "key": key,
            "expires_at": expires_at,
            "created_at": datetime.datetime.now(datetime.timezone.utc),
            "metadata": metadata if metadata is not None else {}
        }
        self._sessions[session_id] = session_data
        logger.info(f"Session '{session_id[:8]}...' created. Expires at {expires_at}.")
        return session_id

    def get_session(self, session_id: str) -> Dict[str, Any] | None:
        """
        Retrieves session data if it's active and not expired.

        Args:
            session_id (str): The ID of the session to retrieve.

        Returns:
            Dict[str, Any] | None: The session data (including key) if valid, else None.
        """
        session_data = self._sessions.get(session_id)
        if session_data:
            if session_data["expires_at"] > datetime.datetime.now(datetime.timezone.utc):
                logger.debug(f"Session '{session_id[:8]}...' retrieved and is active.")
                return session_data
            else:
                self.delete_session(session_id) # Automatically delete expired sessions
                logger.warning(f"Session '{session_id[:8]}...' expired and deleted.")
        logger.debug(f"Session '{session_id[:8]}...' not found or not active.")
        return None

    def delete_session(self, session_id: str) -> bool:
        """
        Deletes a session from the store.

        Args:
            session_id (str): The ID of the session to delete.

        Returns:
            bool: True if the session was deleted, False otherwise.
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.info(f"Session '{session_id[:8]}...' deleted.")
            return True
        logger.warning(f"Attempted to delete non-existent session '{session_id[:8]}...'.")
        return False

    def get_all_active_sessions(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns all currently active (non-expired) sessions.
        """
        active_sessions = {}
        current_time = datetime.datetime.now(datetime.timezone.utc)
        sessions_to_delete = []

        for session_id, session_data in self._sessions.items():
            if session_data["expires_at"] > current_time:
                active_sessions[session_id] = session_data
            else:
                sessions_to_delete.append(session_id)
        
        for session_id in sessions_to_delete:
            self.delete_session(session_id) # Clean up expired sessions

        logger.debug(f"Retrieved {len(active_sessions)} active sessions.")
        return active_sessions

    def clear_all_sessions(self):
        """Clears all sessions from the store."""
        self._sessions = {}
        logger.info("All sessions cleared from SessionStore.")

# Singleton instance
session_store = SessionStore()
