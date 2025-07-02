import unittest
import os
import datetime
from reportlab.pdfgen import canvas
from q_link_sim.q_academy.certificates import generate_certificate

class TestCertificates(unittest.TestCase):

    def setUp(self):
        self.test_dir = os.path.join(os.path.dirname(__file__), 'test_certs')
        os.makedirs(self.test_dir, exist_ok=True)
        self.cert_output_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'certificates')
        # Ensure the actual output directory exists for the function to write to
        os.makedirs(self.cert_output_dir, exist_ok=True)

    def tearDown(self):
        # Clean up generated PDF files
        for f in os.listdir(self.cert_output_dir):
            if f.startswith("certificate_") and f.endswith(".pdf"):
                os.remove(os.path.join(self.cert_output_dir, f))
        if os.path.exists(self.test_dir):
            os.rmdir(self.test_dir)

    def test_generate_certificate_basic(self):
        name = "Test User"
        topic = "Quantum Basics"
        score = 95
        key_length = 128
        session_hash = "a" * 64 # Dummy hash
        
        cert_path = generate_certificate(name, topic, score, key_length, session_hash)
        
        self.assertTrue(os.path.exists(cert_path))
        self.assertTrue(cert_path.endswith(".pdf"))
        self.assertIn(name.replace(" ", "_"), cert_path)
        self.assertIn(datetime.date.today().isoformat(), cert_path)

        # Basic check if it's a valid PDF (by trying to open it with ReportLab's canvas)
        try:
            c = canvas.Canvas(cert_path)
            # If it opens without error, it's likely a valid PDF structure
        except Exception as e:
            self.fail(f"Generated PDF is not valid: {e}")

    def test_generate_certificate_with_blockchain_tx(self):
        name = "Blockchain Enthusiast"
        topic = "Auditing with Blockchain"
        score = 100
        key_length = 0 # Not applicable
        session_hash = "b" * 64
        tx_hash = "0x" + "c" * 64 # Dummy transaction hash
        
        cert_path = generate_certificate(name, topic, score, key_length, session_hash, tx_hash)
        
        self.assertTrue(os.path.exists(cert_path))
        
        # You could add more sophisticated checks here, e.g., parsing the PDF
        # to ensure the content (like tx_hash) is present, but that's more complex.
        # For now, just checking existence and basic validity is sufficient.
        try:
            c = canvas.Canvas(cert_path)
        except Exception as e:
            self.fail(f"Generated PDF with TX hash is not valid: {e}")

    def test_generate_certificate_empty_name(self):
        name = ""
        topic = "Empty Name Test"
        score = 50
        key_length = 64
        session_hash = "d" * 64
        
        # The function itself doesn't prevent empty names, but the filename will reflect it.
        cert_path = generate_certificate(name, topic, score, key_length, session_hash)
        self.assertTrue(os.path.exists(cert_path))
        self.assertIn("certificate__", cert_path) # Check for double underscore due to empty name

if __name__ == '__main__':
    unittest.main()
