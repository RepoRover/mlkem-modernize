FROM python:3.14.7-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.12.15 /uv /uvx /bin/

WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock ./
COPY device/pyproject.toml device/pyproject.toml
COPY gateway/pyproject.toml gateway/pyproject.toml
COPY cloud/pyproject.toml cloud/pyproject.toml
RUN uv sync --frozen --package cloud --no-dev --no-install-workspace

COPY cloud/src cloud/src
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/cloud/src" \
    PYTHONUNBUFFERED=1
EXPOSE 8443
CMD ["python", "-m", "cloud.main"]
