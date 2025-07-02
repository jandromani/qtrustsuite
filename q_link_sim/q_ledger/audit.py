import logging
import json
import hashlib
import jsonpickle
from sqlalchemy.orm import sessionmaker
from q_link_sim.q_ledger.models import LedgerEvent, init_db
from q_link_sim.q_ledger.utils import get_timestamp, calculate_hash
from q_link_sim.blockchain.polygon_bridge import send_to_blockchain # New import

logger = logging.getLogger(__name__)

# Global Session factory, initialized on app startup
Session = None

# Event types that should be anchored to the blockchain
BLOCKCHAIN_ANCHORED_EVENTS = ['QKD_SUCCESS', 'CIPHER_ENCRYPT']

def initialize_audit_db(db_path: str):
    """
    Initializes the SQLAlchemy session factory for the audit ledger.
    Must be called once at application startup.
    """
    global Session
    if Session is None:
        Session = init_db(db_path)
        logger.info(f"Audit ledger initialized at {db_path}")
    else:
        logger.debug("Audit ledger already initialized.")

def register_event(
    event_type: str,
    session_id: str,
    origin_node: str = None,
    dest_node: str = None,
    key_length_bits: int = None,
    message_content: str = None, # Original message or ciphertext for hashing
    event_metadata: dict = None
):
    """
    Registers a critical event in the local audit ledger.
    If the event type is configured for blockchain anchoring, it also sends
    the event hash to the Polygon Mumbai testnet and stores the transaction hash.

    Args:
        event_type (str): Type of event (e.g., QKD_START, QKD_SUCCESS, CIPHER_ENCRYPT).
        session_id (str): UUID of the session related to the event.
        origin_node (str, optional): Origin node name.
        dest_node (str, optional): Destination node name.
        key_length_bits (int, optional): Length of the key in bits, if applicable.
        message_content (str, optional): The message content (original or ciphertext)
                                         to hash for `message_hash`.
        event_metadata (dict, optional): Additional JSON-serializable data for the event.
    """
    if Session is None:
        logger.error("Audit ledger not initialized. Cannot register event.")
        return

    session = Session()
    try:
        timestamp = get_timestamp()
        
        # Calculate message_hash if content is provided
        msg_hash = hashlib.sha256(message_content.encode('utf-8')).hexdigest() if message_content else None

        # Ensure event_metadata is a dictionary
        if event_metadata is None:
            event_metadata = {}

        # Convert event_metadata to JSON string for consistent hashing and storage
        # jsonpickle handles complex types like numpy arrays if they were in metadata
        metadata_json_for_hash_and_storage = jsonpickle.encode(event_metadata)

        # Prepare data for entry_hash calculation
        event_data_for_hash = {
            "timestamp": timestamp,
            "event_type": event_type,
            "session_id": session_id,
            "origin_node": origin_node,
            "dest_node": dest_node,
            "key_length_bits": key_length_bits,
            "message_hash": msg_hash,
            "metadata": metadata_json_for_hash_and_storage # Use the jsonpickled string here
        }
        
        entry_hash = calculate_hash(event_data_for_hash)

        # --- Blockchain Anchoring ---
        tx_hash = None
        if event_type in BLOCKCHAIN_ANCHORED_EVENTS:
            try:
                logger.info(f"Attempting to anchor event {event_type} (Session: {session_id[:8]}...) to blockchain...")
                # Pass entry_hash and session_id for the transaction data
                tx_hash = send_to_blockchain(entry_hash, {"session_id": session_id, "event_type": event_type})
                if tx_hash:
                    # Update the original event_metadata dict (not the jsonpickled one)
                    event_metadata['blockchain_tx_hash'] = tx_hash
                    # Re-encode metadata for storage if it was modified
                    metadata_json_for_hash_and_storage = jsonpickle.encode(event_metadata)
                    logger.info(f"Event anchored in blockchain: https://mumbai.polygonscan.com/tx/{tx_hash}")
                else:
                    logger.warning(f"Blockchain anchoring failed for event {event_type} (Session: {session_id[:8]}...). No transaction hash returned.")
            except Exception as e:
                logger.error(f"Error anchoring event {event_type} (Session: {session_id[:8]}...) to blockchain: {e}", exc_info=True)
                event_metadata['blockchain_anchor_error'] = str(e)
                # Re-encode metadata for storage if it was modified
                metadata_json_for_hash_and_storage = jsonpickle.encode(event_metadata)
        # --- End Blockchain Anchoring ---

        new_event = LedgerEvent(
            timestamp=timestamp,
            event_type=event_type,
            session_id=session_id,
            origin_node=origin_node,
            dest_node=dest_node,
            key_length_bits=key_length_bits,
            message_hash=msg_hash,
            event_metadata=metadata_json_for_hash_and_storage, # Store the final jsonpickled string
            entry_hash=entry_hash
        )
        session.add(new_event)
        session.commit()
        logger.info(f"Event registered in ledger: {event_type} - Session {session_id[:8]}...")
    except Exception as e:
        session.rollback()
        logger.error(f"Error registering event {event_type} for session {session_id}: {e}", exc_info=True)
    finally:
        session.close()

def get_all_events() -> list[dict]:
    """
    Retrieves all events from the ledger as a list of dictionaries.
    """
    if Session is None:
        logger.error("Audit ledger not initialized. Cannot retrieve events.")
        return []

    session = Session()
    try:
        events = session.query(LedgerEvent).all()
        event_list = []
        for event in events:
            event_dict = {
                "id": event.id,
                "timestamp": event.timestamp,
                "event_type": event.event_type,
                "session_id": event.session_id,
                "origin_node": event.origin_node,
                "dest_node": event.dest_node,
                "key_length_bits": event.key_length_bits,
                "message_hash": event.message_hash,
                "metadata": jsonpickle.decode(event.event_metadata) if event.event_metadata else None,
                "entry_hash": event.entry_hash
            }
            event_list.append(event_dict)
        return event_list
    except Exception as e:
        logger.error(f"Error retrieving events from ledger: {e}", exc_info=True)
        return []
    finally:
        session.close()

def verify_ledger_integrity(events_data: list[dict]) -> bool:
    """
    Verifies the integrity of a list of ledger events by recalculating their hashes.

    Args:
        events_data (list[dict]): A list of event dictionaries (e.g., from export).

    Returns:
        bool: True if all events' hashes match their recalculated hashes, False otherwise.
    """
    integrity_ok = True
    for i, event in enumerate(events_data):
        stored_hash = event.get("entry_hash")
        
        # Re-encode metadata for hashing consistency, as it was decoded when retrieved
        metadata_for_hash = event.get("metadata")
        if metadata_for_hash is not None:
            metadata_for_hash = jsonpickle.encode(metadata_for_hash)

        # Create a dictionary for hash calculation, excluding 'id' and 'entry_hash'
        # and ensuring metadata is in its original string form for hashing
        event_data_for_hash = {
            k: v for k, v in event.items() if k not in ["id", "entry_hash", "metadata"]
        }
        event_data_for_hash["metadata"] = metadata_for_hash

        recalculated_hash = calculate_hash(event_data_for_hash)
        
        if stored_hash != recalculated_hash:
            logger.warning(f"Integrity check failed for event ID {event.get('id', 'N/A')} (index {i}). "
                           f"Stored hash: {stored_hash}, Recalculated hash: {recalculated_hash}")
            integrity_ok = False
        else:
            logger.debug(f"Integrity check passed for event ID {event.get('id', 'N/A')}.")
    
    if integrity_ok:
        logger.info("All records verified. Integrity confirmed.")
    else:
        logger.error("Integrity verification failed. Some records have been altered.")
    return integrity_ok
