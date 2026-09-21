# One image, three services. SERVICE picks which module runs.
# Python 3.12 per the project tech constraints.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so code edits do not invalidate the layer.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY services/ ./services/
COPY scripts/ ./scripts/
COPY data/ ./data/

# Run as a non-root user. The mountpoints are created and chowned here so that
# the named volumes inherit this ownership when Docker initialises them.
RUN useradd --create-home --uid 1000 appuser \
    && mkdir -p /keys /var/lib/weather \
    && chown -R appuser:appuser /keys /var/lib/weather /app
USER appuser

ENV KEYS_DIR=/keys \
    PYTHONPATH=/app

# SERVICE is one of: device, gateway, cloud, keygen
ARG SERVICE=cloud
ENV SERVICE=${SERVICE}

# exec form via a shell so $SERVICE expands; keygen is a script, not a module.
CMD ["sh", "-c", "if [ \"$SERVICE\" = keygen ]; then exec python scripts/gen_keys.py --out \"$KEYS_DIR\"; else exec python -m services.$SERVICE.main; fi"]
