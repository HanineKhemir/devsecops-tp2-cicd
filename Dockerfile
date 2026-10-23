FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vulnbank/ ./vulnbank/

ENV PYTHONPATH=/app
ENV FLASK_APP=vulnbank.app
ENV HOST=0.0.0.0

EXPOSE 5000

# TP2 : sonde de sante. Le job DAST du pipeline attend que ce test passe avant de
# lancer OWASP ZAP : on ne scanne jamais une application pas encore demarree
# (sinon ZAP ne trouve rien et la porte DAST serait verte a tort).
# python -c ... plutot que curl : l'image slim ne contient pas curl.
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/', timeout=2).status == 200 else 1)"

CMD ["python", "-m", "vulnbank.app"]
