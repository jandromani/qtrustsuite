import unittest
import numpy as np
from q_link_sim.simulator.qkd_bb84 import (
    generate_random_bits,
    generate_random_bases,
    encode_bits,
    measure_photons,
    compare_bases,
    sift_keys,
    calculate_qber,
    privacy_amplification,
    simulate_bb84,
    apply_polarization,
    measure_photon
)

class TestBB84Generation(unittest.TestCase):

    def test_generate_random_bits(self):
        bits = generate_random_bits(10)
        self.assertEqual(len(bits), 10)
        self.assertTrue(np.all((bits == 0) | (bits == 1)))

    def test_generate_random_bases(self):
        bases = generate_random_bases(10)
        self.assertEqual(len(bases), 10)
        self.assertTrue(np.all((bases == 0) | (bases == 1)))

    def test_apply_polarization(self):
        # Rectilinear basis (0)
        self.assertEqual(apply_polarization(0, 0), "|") # 0 bit -> Vertical
        self.assertEqual(apply_polarization(1, 0), "-") # 1 bit -> Horizontal
        # Diagonal basis (1)
        self.assertEqual(apply_polarization(0, 1), "/") # 0 bit -> Diagonal
        self.assertEqual(apply_polarization(1, 1), "\\") # 1 bit -> Anti-diagonal

    def test_measure_photon_matching_bases(self):
        # Matching rectilinear
        self.assertEqual(measure_photon("|", 0), 0)
        self.assertEqual(measure_photon("-", 0), 1)
        # Matching diagonal
        self.assertEqual(measure_photon("/", 1), 0)
        self.assertEqual(measure_photon("\\", 1), 1)

    def test_measure_photon_mismatching_bases(self):
        # Mismatching bases should yield random results (50/50 chance)
        # We can't assert a specific value, but we can check it's 0 or 1
        results = [measure_photon("|", 1) for _ in range(100)] # Rectilinear photon, diagonal basis
        self.assertTrue(all(r in [0, 1] for r in results))
        self.assertTrue(0 in results and 1 in results) # Should see both 0s and 1s over many trials

        results = [measure_photon("/", 0) for _ in range(100)] # Diagonal photon, rectilinear basis
        self.assertTrue(all(r in [0, 1] for r in results))
        self.assertTrue(0 in results and 1 in results)

    def test_encode_bits(self):
        bits = np.array([0, 1, 0, 1])
        bases = np.array([0, 0, 1, 1]) # Rectilinear, Rectilinear, Diagonal, Diagonal
        encoded = encode_bits(bits, bases)
        # Rectilinear: 0->0, 1->1
        # Diagonal: 0->2, 1->3
        self.assertTrue(np.array_equal(encoded, np.array([0, 1, 2, 3])))

    def test_measure_photons_matching_bases(self):
        photons = np.array([0, 1, 2, 3]) # Encoded from [0,1,0,1] with bases [0,0,1,1]
        bases = np.array([0, 0, 1, 1])   # Matching bases
        measured = measure_photons(photons, bases)
        self.assertTrue(np.array_equal(measured, np.array([0, 1, 0, 1])))

    def test_measure_photons_mismatching_bases(self):
        photons = np.array([0, 1, 2, 3]) # Encoded from [0,1,0,1] with bases [0,0,1,1]
        bases = np.array([1, 1, 0, 0])   # Mismatching bases
        measured = measure_photons(photons, bases)
        # Due to randomness, we can only check the shape and values
        self.assertEqual(len(measured), 4)
        self.assertTrue(np.all((measured == 0) | (measured == 1)))
        # It's highly unlikely to be exactly the original bits
        self.assertFalse(np.array_equal(measured, np.array([0, 1, 0, 1]))) # Should be random

    def test_compare_bases(self):
        alice_bases = np.array([0, 0, 1, 1, 0])
        bob_bases = np.array([0, 1, 1, 0, 0])
        matching = compare_bases(alice_bases, bob_bases)
        self.assertTrue(np.array_equal(matching, np.array([True, False, True, False, True])))

    def test_sift_keys(self):
        original_bits = np.array([0, 1, 0, 1, 0])
        measured_bits = np.array([0, 0, 0, 1, 1]) # Some random measurements
        matching_bases = np.array([True, False, True, False, True])
        sifted_alice = sift_keys(original_bits, measured_bits, matching_bases)
        sifted_bob = sift_keys(measured_bits, measured_bits, matching_bases) # Bob's perspective
        self.assertTrue(np.array_equal(sifted_alice, np.array([0, 0, 0]))) # original_bits at True positions
        self.assertTrue(np.array_equal(sifted_bob, np.array([0, 0, 1]))) # measured_bits at True positions

    def test_calculate_qber(self):
        alice_key = np.array([0, 1, 0, 1])
        bob_key = np.array([0, 1, 1, 0])
        qber = calculate_qber(alice_key, bob_key)
        self.assertEqual(qber, 0.5) # 2 errors out of 4 bits

        alice_key_perfect = np.array([0, 1, 0])
        bob_key_perfect = np.array([0, 1, 0])
        qber_perfect = calculate_qber(alice_key_perfect, bob_key_perfect)
        self.assertEqual(qber_perfect, 0.0)

        qber_empty = calculate_qber(np.array([]), np.array([]))
        self.assertEqual(qber_empty, 0.0)

    def test_privacy_amplification(self):
        sifted_key = np.array([1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1]) # 16 bits
        derived_key = privacy_amplification(sifted_key, output_length_bytes=16)
        self.assertIsInstance(derived_key, bytes)
        self.assertEqual(len(derived_key), 16)
        
        # Test with empty key
        empty_key = np.array([])
        derived_empty = privacy_amplification(empty_key, output_length_bytes=32)
        self.assertEqual(len(derived_empty), 32)
        self.assertEqual(derived_empty, b'\x00' * 32)

        # Test with key shorter than output_length_bytes
        short_key = np.array([1, 0, 1])
        derived_short = privacy_amplification(short_key, output_length_bytes=32)
        self.assertEqual(len(derived_short), 32)

        # Test with key longer than output_length_bytes
        long_key = np.array([1] * 500) # 500 bits
        derived_long = privacy_amplification(long_key, output_length_bytes=16)
        self.assertEqual(len(derived_long), 16)

    def test_simulate_bb84_no_eavesdropping(self):
        num_bits = 100
        (alice_bits, alice_bases, encoded_photons, bob_bases, measured_bits,
         sifted_key_alice, sifted_key_bob, qber, derived_aes_key,
         eve_bases, eve_measured_photons) = simulate_bb84(num_bits, eavesdrop=False)

        self.assertEqual(len(alice_bits), num_bits)
        self.assertEqual(len(alice_bases), num_bits)
        self.assertEqual(len(encoded_photons), num_bits)
        self.assertEqual(len(bob_bases), num_bits)
        self.assertEqual(len(measured_bits), num_bits)
        
        # Without eavesdropping, sifted keys should be identical (or very close due to quantum noise simulation)
        # The measure_photons function introduces randomness if bases don't match,
        # so QBER won't be exactly 0, but should be low (around 0.25 for non-matching bases)
        # For matching bases, it should be 0.
        
        # Check that sifted keys are equal where bases matched
        matching_indices = (alice_bases == bob_bases)
        self.assertTrue(np.array_equal(alice_bits[matching_indices], measured_bits[matching_indices]))

        # QBER should be low (ideally 0 if no noise, but our measure_photons simulates noise for mismatch)
        # The QBER is calculated on the *sifted* keys, which should be identical if no Eve.
        # The only source of error in sifted keys is if the measurement itself was faulty,
        # but our measure_photons is deterministic for matching bases.
        # So, QBER on sifted keys should be 0 if no Eve.
        self.assertEqual(qber, 0.0) # Sifted keys should be identical if no Eve

        self.assertIsInstance(derived_aes_key, bytes)
        self.assertEqual(len(derived_aes_key), 32) # AES-256 key

        self.assertIsNone(eve_bases)
        self.assertIsNone(eve_measured_photons)

    def test_simulate_bb84_with_eavesdropping(self):
        num_bits = 100
        (alice_bits, alice_bases, encoded_photons, bob_bases, measured_bits,
         sifted_key_alice, sifted_key_bob, qber, derived_aes_key,
         eve_bases, eve_measured_photons) = simulate_bb84(num_bits, eavesdrop=True)

        self.assertEqual(len(alice_bits), num_bits)
        self.assertEqual(len(alice_bases), num_bits)
        self.assertEqual(len(encoded_photons), num_bits)
        self.assertEqual(len(bob_bases), num_bits)
        self.assertEqual(len(measured_bits), num_bits)
        
        # With eavesdropping, QBER should be significantly higher (around 0.25)
        # because Eve introduces errors by measuring in random bases.
        self.assertGreater(qber, 0.1) # Should be non-zero and noticeable

        self.assertIsInstance(derived_aes_key, bytes)
        self.assertEqual(len(derived_aes_key), 32) # AES-256 key

        self.assertIsNotNone(eve_bases)
        self.assertIsNotNone(eve_measured_photons)
        self.assertEqual(len(eve_bases), num_bits)
        self.assertEqual(len(eve_measured_photons), num_bits)

    def test_simulate_bb84_output_structure(self):
        num_bits = 100
        (alice_bits, alice_bases, bob_bases, bob_results, compatible_key_bits,
         derived_aes_key, raw_key_length, shared_key_length) = simulate_bb84(num_bits)

        self.assertEqual(len(alice_bits), num_bits)
        self.assertEqual(len(alice_bases), num_bits)
        self.assertEqual(len(bob_bases), num_bits)
        self.assertEqual(len(bob_results), num_bits)
        
        # Compatible key bits length should be <= num_bits
        self.assertLessEqual(len(compatible_key_bits), num_bits)
        
        # Raw key length should be initial num_bits
        self.assertEqual(raw_key_length, num_bits)
        
        # Shared key length should be length of compatible_key_bits
        self.assertEqual(shared_key_length, len(compatible_key_bits))

        # Derived AES key should be 32 bytes (or empty if no compatible bits)
        if shared_key_length > 0:
            self.assertEqual(len(derived_aes_key), 32)
        else:
            self.assertEqual(len(derived_aes_key), 0)

    def test_simulate_bb84_key_consistency(self):
        # Run multiple times and check if compatible bits are indeed consistent
        for _ in range(5):
            num_bits = 200
            (alice_bits, alice_bases, bob_bases, bob_results, compatible_key_bits,
             derived_aes_key, _, _) = simulate_bb84(num_bits)

            # Verify that for matching bases, Alice's bit matches Bob's result
            matching_indices = np.where(alice_bases == bob_bases)[0]
            for idx in matching_indices:
                self.assertEqual(alice_bits[idx], bob_results[idx])
            
            # Verify that compatible_key_bits are indeed Alice's bits at matching indices
            self.assertTrue(np.array_equal(compatible_key_bits, alice_bits[matching_indices]))

    def test_simulate_bb84_no_compatible_bits(self):
        # Force a scenario where no bases match (highly unlikely in random, but for test)
        # Or, test with very small num_bits
        num_bits = 1 # Very small number of bits
        (alice_bits, alice_bases, bob_bases, bob_results, compatible_key_bits,
         derived_aes_key, _, shared_key_length) = simulate_bb84(num_bits)
        
        # It's possible to get 0 compatible bits with small num_bits
        if shared_key_length == 0:
            self.assertEqual(len(derived_aes_key), 0)
            self.assertEqual(len(compatible_key_bits), 0)

if __name__ == '__main__':
    unittest.main()
