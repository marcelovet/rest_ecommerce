FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

ENV UV_PYTHON_DOWNLOADS=0

WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=backend/uv.lock,target=uv.lock \
    --mount=type=bind,source=backend/pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev

COPY ./backend/pyproject.toml ./backend/uv.lock \
    ./backend/alembic.ini ./backend/config.ini \
    ./backend/private_key.pem ./backend/public_key.pem /app/

COPY ./backend/app /app/app

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync

FROM python:3.12-slim-bookworm

RUN addgroup --system app \
    && adduser --system --ingroup app app

COPY --from=builder --chown=app:app /app /app

COPY --chown=app:app ./compose/production/fastapi/start /app/start
RUN sed -i 's/\r$//g' /app/start
RUN chmod +x /app/start

COPY --chown=app:app ./compose/production/fastapi/entrypoint /app/entrypoint
RUN sed -i 's/\r$//g' /app/entrypoint
RUN chmod +x /app/entrypoint

COPY --chown=app:app ./compose/production/fastapi/celery/worker/start /app/start-celeryworker
RUN sed -i 's/\r$//g' /app/start-celeryworker
RUN chmod +x /app/start-celeryworker

COPY --chown=app:app ./compose/production/fastapi/celery/beat/start /app/start-celerybeat
RUN sed -i 's/\r$//g' /app/start-celerybeat
RUN chmod +x /app/start-celerybeat

COPY --chown=app:app ./compose/production/fastapi/celery/flower/start /app/start-flower
RUN sed -i 's/\r$//g' /app/start-flower
RUN chmod +x /app/start-flower

WORKDIR /app

ENV PATH="/app/.venv/bin:$PATH"

ENV PYTHONPATH=/app

USER app

ENTRYPOINT ["/app/entrypoint"]
