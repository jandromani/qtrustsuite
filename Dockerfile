# Use a slim Python 3.10 image as the base
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy only the requirements file first to leverage Docker cache
COPY q_commsec_api/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project directory into the container
COPY q_commsec_api/ q_commsec_api/

# Expose the port Flask will run on
EXPOSE 5000

# Command to run the application:
# It first runs pytest, and if tests pass (exit code 0), it then starts the Flask app.
# 'sh -c' is used to chain commands.
CMD ["sh", "-c", "pytest q_commsec_api/tests/test_crypto.py && python q_commsec_api/app.py"]
