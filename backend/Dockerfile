FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.1 /uv /usr/local/bin/uv

WORKDIR /app

ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PATH="/app/.venv/bin:$PATH" \
    DB_PATH=/app/data/clawguard.db

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev

COPY . .

RUN useradd --system --uid 10001 clawguard \
    && mkdir -p /app/data \
    && chown clawguard:clawguard /app/data

USER clawguard

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
