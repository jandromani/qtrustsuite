import datetime
import hashlib
import json
import jsonpickle # Used for complex object serialization within metadata

def get_timestamp() -> str:
    """Returns the current UTC timestamp in ISO format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def calculate_hash(data: dict) -> str:
    """
    Calculates the SHA-256 hash of a dictionary.
    Ensures consistent serialization for reproducible hashing.
    """
    # Use json.dumps with sort_keys to ensure consistent order for hashing
    # jsonpickle.encode does not support sort_keys directly for its top-level dict,
    # so we ensure any complex objects *within* data are already jsonpickled
    # before passing to json.dumps.
    json_string = json.dumps(data, sort_keys=True, indent=None, separators=(',', ':'))
    return hashlib.sha256(json_string.encode('utf-8')).hexdigest()
