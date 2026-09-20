# Problem Statement

The idea is to prevent devices that cannot perform post-quantum key establishment from becoming e-waste. These devices are hardware-limited and cannot run algorithms such as ML-KEM. Therefore, as a PoC solution, a trusted edge gateway will be placed between the devices and the "cloud".

## Goal

Simulate an ESP8266 weather station sending daily data through a Gateway to a Cloud Service. The trusted Gateway should bridge the device's symmetric encryption to post-quantum key establishment with the Cloud Service.

We can assume the legacy-device supports TLS 1.2

## Structure

```text
device/         # simulator and data/weather_data.csv
gateway/        # device endpoint and ML-KEM client
cloud/          # ML-KEM endpoint and PostgreSQL access
docs/
  AI_USAGE.md   # prompts, results, decisions, verification
pyproject.toml  # uv workspace
uv.lock
docker-compose.yml
```

Each service is a separate uv workspace package, program, and Docker image.

## Data flow

1. Device loops through `device/data/weather_data.csv` at a configurable interval.
2. Device encrypts the data with a per-device symmetric key using AES-256-GCM and sends each observation to Gateway over HTTPS.
3. Gateway authenticates, decrypts, and validates the observation.
4. Gateway authenticates to the Cloud, uses the Cloud's ML-KEM-768 public key to establish a shared secret, derives an AES-256-GCM key, and encrypts and forwards the observation over HTTPS.
5. Cloud uses its ML-KEM-768 private key to recover the shared secret, derives the same AES key, decrypts and validates the observation, and stores it in PostgreSQL.

The Gateway is a trusted plaintext boundary. The PoC modernizes gateway-to-cloud key establishment; it does not provide end-to-end post-quantum encryption between Device and Cloud.

## Cloud

For now simply store the data in a PostgreSQL database.

## Standards

- Each service should be contained and deployable with Docker.
- Use Google-style docstrings to document code.
- Use Pydantic to validate runtime data.
- Log significant AI work in `docs/AI_USAGE.md` as it happens: prompt, relevant result, accepted/modified/rejected decision, and verification.

## Out of Scope

No physical devices. The device should be emulated in a way to shows its hardware limitations.
