FROM python:3.12-slim

WORKDIR /app

COPY backend /app/backend
COPY docker_scanner_image/scanner_runner.py /app/scanner_runner.py

CMD ["python", "/app/scanner_runner.py"]