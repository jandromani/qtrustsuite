import numpy as np
import hashlib
import logging

logger = logging.getLogger(__name__)

def generate_random_bits(num_bits: int) -> np.ndarray:
    """Generates a random array of bits (0 or 1)."""
    return np.random.randint(0, 2, num_bits)

def generate_random_bases(num_bits: int) -> np.ndarray:
    """Generates a random array of bases (0 for rectilinear, 1 for diagonal)."""
    return np.random.randint(0, 2, num_bits)

def apply_polarization(bit: int, basis: int) -> str:
    """
    Applies polarization based on bit and basis.
    0: Rectilinear (0=Vertical | , 1=Horizontal -)
    1: Diagonal (0=Diagonal / , 1=Anti-diagonal \\)
    """
    if basis == 0: # Rectilinear
        return "|" if bit == 0 else "-"
    else: # Diagonal
        return "/" if bit == 0 else "\\"

def measure_photon(photon_polarization: str, basis: int) -> int:
    """
    Measures a photon based on the chosen basis.
    If bases match, result is certain. If not, result is random.
    """
    if basis == 0: # Rectilinear basis
        if photon_polarization == "|" or photon_polarization == "-":
            return 0 if photon_polarization == "|" else 1
        else: # Measuring diagonal photon with rectilinear basis
            return np.random.randint(0, 2) # 50% chance of 0 or 1
    else: # Diagonal basis
        if photon_polarization == "/" or photon_polarization == "\\":
            return 0 if photon_polarization == "/" else 1
        else: # Measuring rectilinear photon with diagonal basis
            return np.random.randint(0, 2) # 50% chance of 0 or 1

def simulate_bb84(num_bits: int = 256) -> tuple:
    """
    Simulates the BB84 Quantum Key Distribution protocol.

    Args:
        num_bits (int): The number of bits Alice sends initially.

    Returns:
        tuple: (alice_bits, alice_bases, bob_bases, bob_results, compatible_key_bits,
                derived_aes_key, raw_key_length, shared_key_length)
    """
    logger.info(f"Starting BB84 simulation with {num_bits} bits.")

    # 1. Alice generates random bits and random bases
    alice_bits = generate_random_bits(num_bits)
    alice_bases = generate_random_bases(num_bits)
    logger.debug(f"Alice generated {num_bits} bits and bases.")

    # 2. Alice polarizes photons and sends them to Bob
    # (In simulation, we just store the polarization Alice would send)
    alice_polarizations = np.array([apply_polarization(alice_bits[i], alice_bases[i]) for i in range(num_bits)])
    logger.debug("Alice polarized photons.")

    # 3. Bob generates random bases and measures photons
    bob_bases = generate_random_bases(num_bits)
    bob_results = np.array([measure_photon(alice_polarizations[i], bob_bases[i]) for i in range(num_bits)])
    logger.debug("Bob measured photons with random bases.")

    # 4. Alice and Bob compare bases (publicly)
    matching_bases_indices = np.where(alice_bases == bob_bases)[0]
    logger.debug(f"Found {len(matching_bases_indices)} matching bases.")

    # 5. Form the raw shared key from compatible bits
    compatible_key_bits = alice_bits[matching_bases_indices] # Alice's bits where bases matched
    
    # In a real scenario, they would also perform error correction and privacy amplification
    # For simulation, we'll assume the compatible bits are the shared key.

    # Derive a strong AES key (32 bytes for AES-256) from the compatible bits
    # Convert compatible_key_bits (numpy array of 0s and 1s) to a byte string
    # This is a simplified derivation. In practice, use KDF like HKDF or PBKDF2.
    if len(compatible_key_bits) == 0:
        logger.warning("No compatible bits generated. Cannot derive AES key.")
        derived_aes_key = b''
    else:
        # Convert numpy array of bits to a byte string
        # Pad with zeros if not a multiple of 8 bits
        bit_string = ''.join(str(b) for b in compatible_key_bits)
        padded_bit_string = bit_string + '0' * ((8 - len(bit_string) % 8) % 8)
        derived_aes_key = int(padded_bit_string, 2).to_bytes(len(padded_bit_string) // 8, byteorder='big')
        
        # If the derived key is not 32 bytes, hash it to get a 32-byte key
        if len(derived_aes_key) != 32:
            logger.warning(f"Derived key length ({len(derived_aes_key)} bytes) is not 32 bytes. Hashing to 32 bytes.")
            derived_aes_key = hashlib.sha256(derived_aes_key).digest()
        
    logger.info(f"BB84 simulation completed. Raw key length: {num_bits}, Shared key length: {len(compatible_key_bits)}.")

    return (
        alice_bits,
        alice_bases,
        bob_bases,
        bob_results,
        compatible_key_bits, # The numpy array of compatible bits
        derived_aes_key,     # The 32-byte derived AES key
        num_bits,            # Raw key length (initial bits sent)
        len(compatible_key_bits) # Shared key length (compatible bits)
    )
