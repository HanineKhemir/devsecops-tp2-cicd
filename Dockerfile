FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vulnbank/ ./vulnbank/

ENV PYTHONPATH=/app
ENV FLASK_APP=vulnbank.app
ENV HOST=0.0.0.0

EXPOSE 5000

CMD ["python", "-m", "vulnbank.app"]
