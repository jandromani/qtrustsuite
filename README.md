# Q-COMMSEC API

This project implements a hybrid quantum-safe communication security API using Flask, simulating post-quantum key exchange (Kyber) and employing AES-256-GCM for symmetric encryption. It includes a web interface for testing, secure session persistence, and robust logging.

## Setup and Running

1.  **Generate your `SESSION_MASTER_KEY`**:
    Run the following Python code to generate a Fernet key:
    ```python
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    print(key.decode())
    \`\`\`
    Copy the output.

2.  **Create a `.env` file**:
    In the root directory of the project (next to `docker-compose.yml`), create a file named `.env` and paste your generated key:
    \`\`\`env
    SESSION_MASTER_KEY=YOUR_GENERATED_KEY_HERE
    \`\`\`
    (Replace `YOUR_GENERATED_KEY_HERE` with the key you copied).

3.  **Build and run the project with Docker Compose**:
    \`\`\`bash
    docker compose up --build
    \`\`\`
    The `--build` flag ensures the Docker image is built before starting the service.

The container will start, automatically run the `pytest` suite, and if all tests pass, it will then launch the Flask API server.

# Para ejecutar el proyecto:
\`\`\`bash
docker compose up
