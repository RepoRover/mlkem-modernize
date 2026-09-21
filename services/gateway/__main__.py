import uvicorn

from pqcnode.config import env_int, env_str

if __name__ == "__main__":
    uvicorn.run(
        "services.gateway.app:app",
        host=env_str("HOST", "0.0.0.0"),  # noqa: S104 - containers bind all interfaces
        port=env_int("PORT", 8080),
        log_config=None,
    )
