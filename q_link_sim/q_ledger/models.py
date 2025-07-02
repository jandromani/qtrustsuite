import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base
import datetime
import logging

logger = logging.getLogger(__name__)

Base = declarative_base()

class LedgerEvent(Base):
    """
    SQLAlchemy ORM model for a single event in the immutable audit ledger.
    """
    __tablename__ = 'ledger_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(String, nullable=False) # ISO format string
    event_type = Column(String, nullable=False) # e.g., QKD_SUCCESS, CIPHER_ENCRYPT, ORCH_SESSION_ASSIGNED
    session_id = Column(String, nullable=False) # UUID of the related session
    origin_node = Column(String, nullable=True)
    dest_node = Column(String, nullable=True)
    key_length_bits = Column(Integer, nullable=True) # Length of key involved, if applicable
    message_hash = Column(String, nullable=True) # SHA256 hash of message content, if applicable
    event_metadata = Column(Text, nullable=True) # JSON string of additional metadata
    entry_hash = Column(String, unique=True, nullable=False) # SHA256 hash of this entry's content

    def __repr__(self):
        return (f"<LedgerEvent(id={self.id}, type='{self.event_type}', "
                f"session='{self.session_id[:8]}...', hash='{self.entry_hash[:8]}...')>")

def init_db(db_path: str):
    """
    Initializes the SQLite database for the audit ledger.
    Creates tables if they don't exist.

    Args:
        db_path (str): The file path for the SQLite database.

    Returns:
        sessionmaker: A configured sessionmaker for interacting with the database.
    """
    db_dir = os.path.dirname(db_path)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
        logger.info(f"Created ledger database directory: {db_dir}")

    engine = create_engine(f'sqlite:///{db_path}')
    Base.metadata.create_all(engine) # Create tables
    logger.info(f"Audit ledger database initialized at {db_path}")
    return sessionmaker(bind=engine)
