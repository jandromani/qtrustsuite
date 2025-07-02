# Q-COMMSEC API

This is the backend API for the Quantum Communication Security (Q-COMMSEC) project. It provides endpoints for key management, session handling, and cryptographic operations.

## Setup

1.  **Clone the repository:**
    \`\`\`bash
    git clone <repository_url>
    cd q-commsec-api-project/q_commsec_api
    \`\`\`

2.  **Create a virtual environment (recommended):**
    \`\`\`bash
    python -m venv venv
    source venv/bin/activate # On Windows: `venv\Scripts\activate`
    \`\`\`

3.  **Install dependencies:**
    \`\`\`bash
    pip install -r requirements.txt
    \`\`\`

4.  **Set up environment variables:**
    Create a `.env` file in the `q_commsec_api` directory with the following content:
    \`\`\`
    FLASK_APP=app.py
    FLASK_ENV=development
    SECRET_KEY="your_secret_key_here"
    \`\`\`
    Replace `"your_secret_key_here"` with a strong, random key.

## Running the API

### Development Mode (Flask)

\`\`\`bash
flask run
\`\`\`
The API will be accessible at `http://127.0.0.1:5000`.

### Production Mode (Gunicorn)

\`\`\`bash
gunicorn --bind 0.0.0.0:5000 app:app
\`\`\`

### Using Docker

1.  **Build the Docker image:**
    \`\`\`bash
    docker build -t q-commsec-api .
    \`\`\`

2.  **Run the Docker container:**
    \`\`\`bash
    docker run -p 5000:5000 q-commsec-api
    \`\`\`

### Using Docker Compose

\`\`\`bash
docker-compose up --build
\`\`\`
This will build and run the API, accessible at `http://localhost:5000`.

## API Endpoints

(To be documented as endpoints are developed)
\`\`\`

### Archivo: `q_commsec_api/__init__.py`

```python file="q_commsec_api/__init__.py"
# This file makes the 'q_commsec_api' directory a Python package.
