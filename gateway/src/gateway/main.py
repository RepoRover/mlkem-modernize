"""Gateway HTTPS process entry point."""

import logging
import ssl

import uvicorn
from pydantic import ValidationError

from gateway.app import create_app
from gateway.config import Settings
from gateway.errors import validation_codes
from gateway.logging_config import configure_json_logging

logger = logging.getLogger("gateway")


def main() -> None:
    """Run the Gateway HTTPS service from environment configuration."""
    configure_json_logging("gateway")
    try:
        settings = Settings.from_environment()
    except ValidationError as error:
        codes = validation_codes(error)
        logger.error(
            "event=settings_rejected errors=%s",
            codes,
            extra={"event": "settings_rejected", "errors": codes},
        )
        raise SystemExit(1) from None

    config = uvicorn.Config(
        create_app(settings=settings),
        host="0.0.0.0",
        port=8443,
        log_config=None,
        limit_concurrency=64,
        backlog=128,
        timeout_graceful_shutdown=10,
        ssl_certfile=str(settings.tls_cert_file),
        ssl_keyfile=str(settings.tls_key_file),
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
    )
    config.load()
    if isinstance(config.ssl, ssl.SSLContext):
        config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
