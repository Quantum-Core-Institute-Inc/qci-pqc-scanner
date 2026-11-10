FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY src/ ./src/
COPY docs/ ./docs/

RUN pip install --no-cache-dir -e .

# Offline-friendly: no external calls at runtime
ENTRYPOINT ["qci-pqc"]
CMD ["--help"]
