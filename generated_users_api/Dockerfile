# Multi-stage Dockerfile optimizado para producción y desarrollo
# Asume estructura estándar:
#  - app/ (código de la app)
#  - alembic/ (scripts alembic)
#  - alembic.ini
#  - requirements.txt (incluye: fastapi, uvicorn, gunicorn, alembic, psycopg[binary], etc.)
#  - requirements-dev.txt (opcional)

# ---------- Base ----------
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VENV_PATH=/opt/venv

ARG APP_USER=appuser
ARG APP_UID=10001

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/*

# Usuario no-root
RUN useradd -u ${APP_UID} -m -s /usr/sbin/nologin ${APP_USER}

# Crear venv y actualizar toolchain
RUN python -m venv ${VENV_PATH} \
    && ${VENV_PATH}/bin/pip install --upgrade pip setuptools wheel

ENV PATH="${VENV_PATH}/bin:${PATH}"
WORKDIR /app

# ---------- Builder (deps) ----------
FROM base AS builder
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ---------- Runtime (producción) ----------
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VENV_PATH=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Copiar venv con dependencias
COPY --from=base ${VENV_PATH} ${VENV_PATH}
COPY --from=builder ${VENV_PATH} ${VENV_PATH}

WORKDIR /app

# Copiar app y migraciones
COPY alembic.ini /app/alembic.ini
COPY alembic /app/alembic
COPY app /app/app

ENV ALEMBIC_CONFIG=/app/alembic.ini

# Usuario no-root
ARG APP_USER=appuser
ARG APP_UID=10001
RUN useradd -u ${APP_UID} -m -s /usr/sbin/nologin ${APP_USER} || true
USER ${APP_USER}

EXPOSE 8000

# Variables de runtime (puede sobreescribir en despliegue)
ENV APP_MODULE="app.main:app" \
    GUNICORN_WORKERS=3 \
    GUNICORN_TIMEOUT=60

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

# Ejecuta migraciones al arrancar y luego el servidor
CMD alembic upgrade head && \
    gunicorn --workers ${GUNICORN_WORKERS} \
             --worker-class uvicorn.workers.UvicornWorker \
             --bind 0.0.0.0:8000 \
             --timeout ${GUNICORN_TIMEOUT} \
             ${APP_MODULE}

# ---------- Dev (recargas) ----------
FROM runtime AS dev
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    nano iputils-ping netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
COPY requirements-dev.txt /tmp/requirements-dev.txt
RUN if [ -f /tmp/requirements-dev.txt ]; then \
      pip install --no-cache-dir -r /tmp/requirements-dev.txt; \
    fi
USER ${APP_USER}
CMD bash -lc "alembic upgrade head && uvicorn ${APP_MODULE} --host 0.0.0.0 --port 8000 --reload"
