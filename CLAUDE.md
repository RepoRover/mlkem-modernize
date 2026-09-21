# Project: PQC Migration of a Legacy Edge–Cloud Weather System

## Purpose
University group project (7 weeks). We modernize a small legacy edge–cloud system for
post-quantum cryptography. The focus is SAFE INTEGRATION of ML-KEM into a legacy
environment, plus testing, CI/CD, deployment and observability. We are NOT implementing
ML-KEM ourselves; we use an existing, well-maintained library.

## System
Three components, each its own service/container:
1. **Legacy device (simulated)**: replays real weather data from `data/` (inspect the
   format before assuming anything). Sends readings periodically to the gateway. Uses
   classical crypto only and is treated as NON-UPGRADEABLE firmware.
2. **Edge gateway**: receives device readings, validates them, and forwards them to the cloud.
   This is where post-quantum protection starts.
3. **Cloud service**: receives, validates, and stores readings. Exposes a minimal read API.

## Tech constraints
- Language: Python 3.12 unless a strong reason exists otherwise (justify in DECISIONS.md).
- Crypto: use established libraries only (e.g., liboqs-python for ML-KEM, `cryptography`
  for X25519/HKDF/AES-GCM). Evaluate and justify the choice; do not hand-roll primitives.
- Containerized with Docker / docker-compose.
- Keep it small. Prefer clarity over features.

## Crypto rules (non-negotiable)
- ML-KEM is used for KEY ESTABLISHMENT only, never to encrypt payloads directly.
- Hybrid key exchange on the PQC path: X25519 + ML-KEM-768, secrets combined via HKDF
  with a clear context/label binding (include both public keys/ciphertexts in the transcript).
- Payloads use AEAD (AES-256-GCM or ChaCha20-Poly1305) with unique nonces per key.
- Session keys must be rotated/re-established; define when.
- No silent downgrade: any fallback to classical-only must be explicit, configurable,
  logged, and visible in metrics.
- Never log keys, shared secrets, or plaintext payloads.

## Working rules for you (Claude)
- You are an assistant. Your output will be critically reviewed and treated as untrusted.
- Before writing code, state your plan and assumptions, and wait if something is ambiguous.
- For every significant change, append an entry to `docs/DECISIONS.md`: what you did,
  alternatives considered, known weaknesses, and what should be verified by humans.
- Explicitly flag anything you are unsure about (especially crypto and security details).
- Write tests alongside code. Don't claim something works without a test demonstrating it.
- Small, focused commits-worth of change per task.