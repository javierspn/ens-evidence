# Deliberately vulnerable: no USER (semgrep dockerfile.security.missing-user,
# trivy DS-0002) and no HEALTHCHECK (trivy DS-0026).
FROM python:3.12-slim
COPY app /app
RUN pip install -r /app/requirements.txt
CMD ["python", "/app/main.py"]
