# Benchmark — pqc-hybrid

- **Run:** 2026-09-21T10:43:54Z
- **Suite:** hop2 hybrid: X25519 + ML-KEM-768 / ECDSA-P256 / HKDF-SHA256 / AES-256-GCM; hop1 + fallback: ECDH-P256
- **Iterations:** 300
- **Python:** 3.10.11 on Windows AMD64
- **Mode:** in-process (no network)

Latency is reported as median and p95. Compare medians; means are dominated by outliers.

## Primitives

| operation | median (ms) | p95 (ms) | min (ms) | n |
|---|---:|---:|---:|---:|
| `ec_keygen_p256` | 0.0249 | 0.0430 | 0.0241 | 300 |
| `ecdh_p256` | 0.0680 | 0.0871 | 0.0664 | 300 |
| `ecdsa_sign_p256` | 0.0407 | 0.0831 | 0.0397 | 300 |
| `ecdsa_verify_p256` | 0.0955 | 0.1500 | 0.0934 | 300 |
| `hkdf_sha256` | 0.0077 | 0.0078 | 0.0075 | 300 |
| `pubkey_encode` | 0.0070 | 0.0204 | 0.0069 | 300 |
| `pubkey_decode` | 0.0166 | 0.0214 | 0.0162 | 300 |
| `aes256gcm_encrypt_reading` | 0.0046 | 0.0048 | 0.0045 | 300 |
| `x25519_keygen` | 0.0503 | 0.0944 | 0.0491 | 300 |
| `x25519_exchange` | 0.0479 | 0.0948 | 0.0463 | 300 |
| `x25519_pubkey_decode` | 0.0044 | 0.0089 | 0.0043 | 300 |
| `mlkem768_keygen` | 0.2416 | 0.4189 | 0.2348 | 300 |
| `mlkem768_ek_parse_and_validate` | 0.0283 | 0.0512 | 0.0275 | 300 |
| `mlkem768_encapsulate` | 0.0643 | 0.0737 | 0.0634 | 300 |
| `mlkem768_decapsulate` | 0.0968 | 0.1025 | 0.0950 | 300 |
| `aes256gcm_decrypt_reading` | 0.0110 | 0.0178 | 0.0092 | 300 |

## Key establishment (crypto only)

| operation | median (ms) | p95 (ms) | min (ms) | n |
|---|---:|---:|---:|---:|
| `hop1_static_static_ecdh` | 0.0815 | 0.1602 | 0.0796 | 300 |
| `hop2_ephemeral_ecdhe_mutual_ecdsa` | 0.6653 | 1.0351 | 0.6407 | 300 |
| `hop2_hybrid_x25519_mlkem768` | 1.1578 | 1.8823 | 1.0424 | 300 |

## Handshake round trip (incl. HTTP + JSON)

| operation | median (ms) | p95 (ms) | min (ms) | n |
|---|---:|---:|---:|---:|
| `hop1_handshake_roundtrip` | 3.4150 | 4.1711 | 3.0207 | 60 |
| `hop2_handshake_roundtrip` | 4.4625 | 5.2297 | 3.8728 | 60 |
| `hop2_v2_hybrid_handshake_roundtrip` | 4.0262 | 4.7637 | 3.5640 | 60 |
| `hop2_v2_classical_handshake_roundtrip` | 3.7899 | 5.5117 | 3.1210 | 60 |

## Per-message latency

| operation | median (ms) | p95 (ms) | min (ms) | n |
|---|---:|---:|---:|---:|
| `end_to_end_reading_both_hops` | 5.2366 | 6.5719 | 4.6796 | 300 |
| `hop1_only_reading` | 5.1910 | 6.5654 | 4.5072 | 300 |

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
| `x25519_public_key` | 32 |
| `mlkem768_encapsulation_key` | 1184 |
| `mlkem768_ciphertext` | 1088 |
| `mlkem768_shared_secret` | 32 |
| `hop1_client_hello` | 122 |
| `hop1_server_hello` | 188 |
| `hop1_total` | 310 |
| `hop2_client_hello` | 316 |
| `hop2_server_hello` | 394 |
| `hop2_total` | 710 |
| `hop2_v2_hybrid_client_hello` | 2095 |
| `hop2_v2_hybrid_server_hello` | 1864 |
| `hop2_v2_hybrid_total` | 3959 |
| `hop2_v2_classical_client_hello` | 386 |
| `hop2_v2_classical_server_hello` | 428 |
| `hop2_v2_classical_total` | 814 |
| `reading_plaintext_json` | 233 |
| `reading_ciphertext_with_tag` | 249 |
| `hop1_ingest_frame_on_wire` | 416 |
| `gateway_envelope_plaintext_json` | 347 |
| `gateway_envelope_ciphertext_with_tag` | 363 |

## Before / after: adding ML-KEM-768

Baseline `legacy-baseline` (2026-09-21T10:11:23Z) vs `pqc-hybrid` (2026-09-21T10:43:54Z).

### Handshake latency (median, ms)

| measurement | classical (before) | hybrid (after) | delta |
|---|---:|---:|---:|
| hop 2 key establishment (crypto only) | 0.7457 | 1.1578 | +55.3% |
| hop 2 handshake round trip | 4.6391 | 4.0262 | -13.2% |
| hop 1 key establishment (unchanged) | 0.0915 | 0.0815 | -10.9% |
| per-message, both hops (unchanged) | 6.0292 | 5.2366 | -13.1% |

### Handshake size (bytes on the wire)

| measurement | classical (before) | hybrid (after) | delta |
|---|---:|---:|---:|
| hop 2 ClientHello | 316 | 2095 | +563.0% |
| hop 2 ServerHello | 394 | 1864 | +373.1% |
| hop 2 handshake total | 710 | 3959 | +457.6% |
| hop 1 handshake total (unchanged) | 310 | 310 | +0.0% |

### Per-message size (must be unchanged)

| measurement | before | after | delta |
|---|---:|---:|---:|
| reading plaintext | 233 | 233 | +0.0% |
| reading ciphertext + tag | 249 | 249 | +0.0% |
| ingest frame on the wire | 416 | 416 | +0.0% |

**Reading this table.** ML-KEM establishes a key; it never touches the payload. So the handshake rows are expected to grow and the per-message rows are expected to be identical. A non-zero delta in the per-message section means the KEM has leaked onto the data path, which `CLAUDE.md` forbids.

Hop 1 rows are a control: the device is non-upgradeable, so any movement there is measurement noise rather than a real change.

### Overhead

- AEAD expansion: **16 bytes** (the GCM tag).
- Framing (base64 + JSON envelope): **167 bytes**.
- Total per reading: **183 bytes**, a **1.785x** expansion over the plaintext.

## What to watch after PQC

ML-KEM-768 changes the handshake, not the message path. Expect:

- `hop2_*` handshake latency and size to grow; `hop1_*` to be unchanged.
- ML-KEM-768 encapsulation key is 1184 B and a ciphertext is 1088 B, against 65 B for a P-256 public key — so the hop 2 handshake should grow by roughly 2.2 KB before base64, ~3 KB after.
- Per-message latency and size should be **unchanged**: the KEM establishes the key and never touches the payload. If per-message numbers move, something is wrong.

