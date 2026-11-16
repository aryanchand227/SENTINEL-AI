# SENTINEL AI — Backend Dockerfile
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast deterministic builds
RUN pip install --no-cache-dir uv

COPY pyproject.toml .
RUN uv pip install --system --no-cache . "langgraph>=0.2.0,<1.0" "langchain-core>=0.3.0,<1.0" "elasticsearch[async]>=8.16.0,<9.0"

FROM python:3.12-slim AS runner

WORKDIR /app

# Create non-privileged service user
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -m -s /bin/bash sentinel

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY alembic.ini .
COPY alembic alembic
COPY backend backend

RUN mkdir -p /app/artifacts && chown -R sentinel:sentinel /app

USER sentinel

ENV PYTHONUNBUFFERED=1 \
    PORT=8000

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
