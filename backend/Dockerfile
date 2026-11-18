FROM ghcr.io/astral-sh/uv:0.13.9 AS uv

FROM python:3.14.10-slim-trixie AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    PATH=/opt/venv/bin:$PATH \
    ROLA_MEDIA_ROOT=/storage/media \
    ROLA_STATIC_ROOT=/storage/static
RUN useradd --uid 1000 --user-group rola \
    && mkdir -p /storage/media /storage/static \
    && chown -R rola:rola /storage
WORKDIR /app
EXPOSE 8000

FROM base AS builder
ENV UV_COMPILE_BYTECODE=1
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN --mount=from=uv,source=/uv,target=/bin/uv \
    --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable --no-install-project
COPY . .
RUN --mount=from=uv,source=/uv,target=/bin/uv \
    --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

FROM base AS development
COPY pyproject.toml uv.lock ./
RUN --mount=from=uv,source=/uv,target=/bin/uv \
    --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project
USER rola
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

FROM base AS production
ENV WEB_CONCURRENCY=2
COPY --from=builder /opt/venv /opt/venv
COPY manage.py ./
USER rola
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--no-control-socket", \
    "--timeout", "120", \
    "--access-logfile", "-", \
    "--access-logformat", "%(h)s %(l)s %(u)s %(t)s \"%(m)s %(U)s %(H)s\" %(s)s %(b)s \"%(a)s\"", \
    "rola.config.wsgi:application"]
