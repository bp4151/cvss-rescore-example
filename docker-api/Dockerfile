FROM python:3.11-slim-bullseye

WORKDIR /app

RUN pip install fastapi "uvicorn[standard]" cvss-rescore
COPY docker-api.py .

CMD ["uvicorn", "docker-api:app", "--host", "0.0.0.0", "--port", "80"]
