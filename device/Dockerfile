FROM python:3.14.7-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.12.17 /uv /uvx /bin/

WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock ./
COPY device/pyproject.toml device/pyproject.toml
COPY gateway/pyproject.toml gateway/pyproject.toml
COPY cloud/pyproject.toml cloud/pyproject.toml
RUN uv sync --locked --package device --no-dev --no-install-workspace

COPY device/src device/src
COPY device/data device/data
RUN uv sync --locked --package device --no-dev --no-editable

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1
USER 10001:10001
CMD ["mlkem-device"]
