"""Cloud HTTPS process entry point."""

import logging
import ssl

import uvicorn
from pydantic import ValidationError

from cloud.app import create_app
from cloud.config import Settings
from cloud.errors import validation_codes

logger = logging.getLogger("cloud")


def main() -> None:
    """Run the Cloud HTTPS service from environment configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s service=cloud level=%(levelname)s %(message)s",
    )
    try:
        settings = Settings()  # pyright: ignore[reportCallIssue]
    except ValidationError as error:
        logger.error("event=settings_rejected errors=%s", validation_codes(error))
        raise SystemExit(1) from None
    config = uvicorn.Config(
        create_app(settings=settings),
        host="0.0.0.0",
        port=8443,
        log_config=None,
        ssl_certfile=str(settings.tls_cert_file),
        ssl_keyfile=str(settings.tls_key_file),
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
    )
    config.load()
    if isinstance(config.ssl, ssl.SSLContext):
        config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
