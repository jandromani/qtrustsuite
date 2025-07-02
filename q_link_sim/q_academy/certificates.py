import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.colors import black, blue
import datetime
import logging

logger = logging.getLogger(__name__)

def generate_certificate(name: str, topic: str, score: int, key_length: int, session_hash: str, tx_hash: str = None) -> str:
    """
    Generates a PDF certificate of completion for an educational session.

    Args:
        name (str): Name of the student.
        topic (str): Topic of the completed session.
        score (int): Score achieved in the session.
        key_length (int): Length of the key obtained (if applicable).
        session_hash (str): Unique hash of the session.
        tx_hash (str, optional): Blockchain transaction hash if anchored.

    Returns:
        str: The file path to the generated PDF certificate.
    """
    cert_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'certificates')
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)
        logger.info(f"Created certificates directory: {cert_dir}")

    file_name = f"certificate_{name.replace(' ', '_')}_{datetime.date.today().isoformat()}.pdf"
    file_path = os.path.join(cert_dir, file_name)

    c = canvas.Canvas(file_path, pagesize=letter)
    width, height = letter

    # Title
    c.setFont("Helvetica-Bold", 36)
    c.setFillColor(blue)
    c.drawCentredString(width / 2.0, height - 1.5 * inch, "Certificado de Finalizacion")

    # Subtitle
    c.setFont("Helvetica", 20)
    c.setFillColor(black)
    c.drawCentredString(width / 2.0, height - 2.5 * inch, "Otorgado a:")

    # Student Name
    c.setFont("Helvetica-Bold", 30)
    c.drawCentredString(width / 2.0, height - 3.5 * inch, name.upper())

    # For completing
    c.setFont("Helvetica", 18)
    c.drawCentredString(width / 2.0, height - 4.5 * inch, "Por completar exitosamente la practica de:")

    # Topic
    c.setFont("Helvetica-Bold", 24)
    c.drawCentredString(width / 2.0, height - 5.2 * inch, topic)

    # Details
    c.setFont("Helvetica", 14)
    details = [
        f"Puntuacion Obtenida: {score} puntos",
        f"Longitud de Clave (si aplica): {key_length} bits",
        f"Fecha de Emision: {datetime.date.today().strftime('%Y-%m-%d')}",
        f"ID de Sesion (Hash): {session_hash[:16]}..."
    ]
    
    if tx_hash:
        details.append(f"Anclado en Blockchain (TX Hash): {tx_hash[:16]}...")
        details.append(f"Ver en Polygonscan: https://mumbai.polygonscan.com/tx/{tx_hash}")

    y_offset = height - 6.5 * inch
    for detail in details:
        c.drawCentredString(width / 2.0, y_offset, detail)
        y_offset -= 0.3 * inch

    # Footer
    c.setFont("Helvetica-Oblique", 12)
    c.drawCentredString(width / 2.0, 1.0 * inch, "Q-LINK SIM - Simulador de Red Cuantica")
    c.drawCentredString(width / 2.0, 0.7 * inch, "Este certificado es generado por el simulador y no tiene validez legal.")

    c.save()
    logger.info(f"Certificate generated for {name} at {file_path}")
    return file_path
