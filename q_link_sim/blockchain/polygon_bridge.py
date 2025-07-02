import os, logging, json                 # ← json faltaba
from dotenv import load_dotenv
load_dotenv()    
from web3 import Web3
from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3.middleware.geth_poa import geth_poa_middleware # Required for PoA networks like Polygon Mumbai

logger = logging.getLogger(__name__)

# ABI for a simple contract that stores a string (hash) and an associated data string
# This ABI is for a contract with a function like:
# function storeHash(string memory _hash, string memory _data) public
# event HashStored(string indexed _hash, string _data, address indexed sender);
CONTRACT_ABI = [
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "_hash",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "_data",
                "type": "string"
            }
        ],
        "name": "storeHash",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "anonymous": False,
        "inputs": [
            {
                "indexed": True,
                "internalType": "string",
                "name": "_hash",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "_data",
                "type": "string"
            },
            {
                "indexed": True,
                "internalType": "address",
                "name": "sender",
                "type": "address"
            }
        ],
        "name": "HashStored",
        "type": "event"
    }
]

w3 = None
contract = None
account: LocalAccount = None
CONTRACT_ADDRESS = None

def initialize_web3():
    """
    Initializes the Web3 instance and contract.
    Loads RPC URL, private key, and contract address from environment variables.
    """
    global w3, contract, account, CONTRACT_ADDRESS

    rpc_url = os.getenv("POLYGON_MUMBAI_RPC_URL")
    private_key = os.getenv("PRIVATE_KEY")
    CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")

    if not rpc_url or not private_key or not CONTRACT_ADDRESS:
        logger.error("Missing Polygon Mumbai RPC URL, Private Key, or Contract Address in environment variables.")
        w3 = None
        contract = None
        account = None
        return False

    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0) # For PoA networks

        if not w3.is_connected():
            logger.error(f"Failed to connect to Web3 provider at {rpc_url}")
            w3 = None
            return False

        account = Account.from_key(private_key)
        contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
        
        logger.info(f"Web3 initialized. Connected to {rpc_url}. Account: {account.address}")
        logger.info(f"Contract initialized at: {CONTRACT_ADDRESS}")
        return True
    except Exception as e:
        logger.error(f"Error initializing Web3: {e}", exc_info=True)
        w3 = None
        contract = None
        account = None
        return False

def send_to_blockchain(data_hash: str, metadata: dict = None) -> str | None:
    """
    Sends a hash and associated metadata to the blockchain.
    
    Args:
        data_hash (str): The hash string to store on the blockchain.
        metadata (dict, optional): Additional metadata to store as a JSON string.
                                   E.g., {"session_id": "...", "event_type": "..."}
    Returns:
        str | None: The transaction hash if successful, None otherwise.
    """
    if not w3 or not contract or not account:
        logger.error("Web3 not initialized. Cannot send to blockchain.")
        if not initialize_web3(): # Try to re-initialize if not already
            return None

    try:
        # Convert metadata dict to JSON string
        metadata_json_str = json.dumps(metadata) if metadata else ""

        # Build the transaction
        # Use the 'storeHash' function from your smart contract
        transaction = contract.functions.storeHash(data_hash, metadata_json_str).build_transaction({
            'from': account.address,
            'nonce': w3.eth.get_transaction_count(account.address),
            'gasPrice': w3.eth.gas_price,
            'gas': 200000 # Estimate gas or use a higher safe value
        })

        # Sign the transaction
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key=account.key)

        # Send the transaction
        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        
        logger.info(f"Transaction sent. Tx Hash: {tx_hash.hex()}")
        
        # Wait for the transaction to be mined (optional, but good for confirmation)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        if receipt.status == 1:
            logger.info(f"Transaction confirmed in block {receipt.blockNumber}. Hash: {data_hash}")
            return tx_hash.hex()
        else:
            logger.error(f"Transaction failed. Receipt: {receipt}")
            return None

    except Exception as e:
        logger.error(f"Error sending hash to blockchain: {e}", exc_info=True)
        return None

# Initialize Web3 when the module is imported
initialize_web3()

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv() # Load environment variables from .env file

    # Configure logging for standalone execution
    from q_link_sim.logging_config import setup_logging
    LOG_FILE_PATH_BLOCKCHAIN = os.path.join(os.path.dirname(__file__), '..', 'data', 'logs', 'blockchain.log')
    setup_logging(log_file_path=LOG_FILE_PATH_BLOCKCHAIN, level=logging.INFO)

    print("--- Polygon Bridge Test ---")
    
    # Ensure Web3 is initialized
    if not w3:
        print("Web3 initialization failed. Check your .env file and network connection.")
    else:
        test_hash = "a" * 64 # Example SHA256 hash
        test_metadata = {"test_id": "123", "source": "python_script"}
        print(f"Attempting to send hash: {test_hash} with metadata: {test_metadata}")
        
        tx_hash = send_to_blockchain(test_hash, test_metadata)
        
        if tx_hash:
            print(f"\nSuccessfully sent to blockchain. Transaction Hash: {tx_hash}")
            print(f"View on Polygonscan: https://mumbai.polygonscan.com/tx/{tx_hash}")
        else:
            print("\nFailed to send to blockchain. Check logs for errors.")
