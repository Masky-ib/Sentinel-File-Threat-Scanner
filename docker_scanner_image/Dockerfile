# Use a small official Python image for the scanner container.
# The slim image keeps Sentinel's custom Docker image smaller while still providing Python.
FROM python:3.12-slim

# Set the working directory inside the container.
# All later commands run from /app unless another directory is specified.
WORKDIR /app

# Copy Sentinel's backend package into the container.
# This is needed because scanner_runner.py imports the backend scanner code.
#
# The backend folder includes:
# - scanner.py
# - rules.py
# - supporting backend package files
COPY backend /app/backend

# Copy the Docker scanner runner into the container.
# scanner_runner.py is the safe container entry point.
#
# It receives the mounted file path, runs Sentinel's rule-based scanner,
# and prints JSON back to the host application.
COPY docker_scanner_image/scanner_runner.py /app/scanner_runner.py

# Default command for the container.
# docker_scanner.py normally passes the file path when running the image.
# This CMD still makes the image runnable by itself.
CMD ["python", "/app/scanner_runner.py"]