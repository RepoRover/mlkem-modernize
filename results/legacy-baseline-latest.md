# Benchmark — legacy-baseline

- **Run:** 2026-09-21T10:11:23Z
- **Suite:** ECDH-P256 / ECDSA-P256 / HKDF-SHA256 / AES-256-GCM
- **Iterations:** 200
- **Python:** 3.10.11 on Windows AMD64
- **Mode:** in-process (no network)

Latency is reported as median and p95. Compare medians; means are dominated by outliers.

## Primitives

| operation | median (ms) | p95 (ms) | min (ms) | n |
|---|---:|---:|---:|---:|
| `ec_keygen_p256` | 0.0227 | 0.0281 | 0.0224 | 200 |
| `ecdh_p256` | 0.0672 | 0.0725 | 0.0663 | 200 |
| `ecdsa_sign_p256` | 0.0417 | 0.0566 | 0.0408 | 200 |
| `ecdsa_verify_p256` | 0.0947 | 0.1025 | 0.0928 | 200 |
| `hkdf_sha256` | 0.0152 | 0.0156 | 0.0149 | 200 |
| `pubkey_encode` | 0.0072 | 0.0072 | 0.0071 | 200 |
| `pubkey_decode` | 0.0142 | 0.0147 | 0.0140 | 200 |
| `aes256gcm_encrypt_reading` | 0.0048 | 0.0049 | 0.0046 | 200 |
| `aes256gcm_decrypt_reading` | 0.0088 | 0.0089 | 0.0086 | 200 |

## Key establishment (crypto only)

| operation | median (ms) | p95 (ms) | min (ms) | n |
|---|---:|---:|---:|---:|
| `hop1_static_static_ecdh` | 0.0915 | 0.1004 | 0.0891 | 200 |
| `hop2_ephemeral_ecdhe_mutual_ecdsa` | 0.7457 | 0.9884 | 0.7248 | 200 |

## Handshake round trip (incl. HTTP + JSON)

| operation | median (ms) | p95 (ms) | min (ms) | n |
|---|---:|---:|---:|---:|
| `hop1_handshake_roundtrip` | 3.9452 | 4.7421 | 3.4380 | 40 |
| `hop2_handshake_roundtrip` | 4.6391 | 5.6767 | 4.1734 | 40 |

## Per-message latency

| operation | median (ms) | p95 (ms) | min (ms) | n |
|---|---:|---:|---:|---:|
| `end_to_end_reading_both_hops` | 6.0292 | 7.9410 | 4.9292 | 200 |
| `hop1_only_reading` | 5.6900 | 7.4375 | 4.7415 | 200 |

## Message sizes

| element | bytes |
|---|---:|
| `p256_public_key_x962_uncompressed` | 65 |
| `ecdsa_p256_signature_der` | 71 |
| `handshake_nonce` | 16 |
| `session_id` | 16 |
| `aead_nonce` | 12 |
| `aead_tag` | 16 |
| `session_key` | 32 |
| `hop1_client_hello` | 122 |
| `hop1_server_hello` | 188 |
| `hop1_total` | 310 |
| `hop2_client_hello` | 316 |
| `hop2_server_hello` | 394 |
| `hop2_total` | 710 |
| `reading_plaintext_json` | 233 |
| `reading_ciphertext_with_tag` | 249 |
| `hop1_ingest_frame_on_wire` | 416 |
| `gateway_envelope_plaintext_json` | 347 |
| `gateway_envelope_ciphertext_with_tag` | 363 |

### Overhead

- AEAD expansion: **16 bytes** (the GCM tag).
- Framing (base64 + JSON envelope): **167 bytes**.
- Total per reading: **183 bytes**, a **1.785x** expansion over the plaintext.

## What to watch after PQC

ML-KEM-768 changes the handshake, not the message path. Expect:

- `hop2_*` handshake latency and size to grow; `hop1_*` to be unchanged.
- ML-KEM-768 encapsulation key is 1184 B and a ciphertext is 1088 B, against 65 B for a P-256 public key — so the hop 2 handshake should grow by roughly 2.2 KB before base64, ~3 KB after.
- Per-message latency and size should be **unchanged**: the KEM establishes the key and never touches the payload. If per-message numbers move, something is wrong.

