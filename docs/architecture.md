# Architecture

## Components

| Service | Runtime | Role |
|---|---|---|
| `legacy-device` | Python 3.9, cryptography 3.4.8 | Replays 366 daily weather readings. Frozen firmware: 48 MB, 0.1 CPU, read-only rootfs, no route off the edge network. Uses `urllib.request` rather than an HTTP client package. |
| `gateway` | Python 3.12, cryptography 50 | Terminates the device's legacy session and opens a separate post-quantum session to the cloud. The broker. |
| `cloud` | Python 3.12, FastAPI, SQLite | Accepts either suite, persists readings, exposes a query API, health probes, and metrics. Can refuse the legacy suite by policy. |
| `tap` | Python 3.12 | Passive wiretap on each link. Forwards untouched, appends to a JSON Lines capture. |
| `harvester` | Python 3.12 | Offline attacker. Run on demand, not part of the running stack. |

## Why a gateway exists

The device cannot adopt ML-KEM. The reason is specific, and the obvious
explanation is wrong.

It is **not** the Python version: `cryptography>=48` installs cleanly on Python
3.9 and ML-KEM-768 works there, which
`test_python_version_alone_would_not_have_blocked_mlkem` asserts so nobody can
quietly restate the convenient version. It is **not** the CPU or memory budget
either: ML-KEM keygen costs 0.26 ms and the device idles at 20.8 MiB of its
48 MiB cap.

What blocks it is the update path:

1. the crypto dependency is **pinned** to an August 2021 build inside an
   immutable image;
2. the container sits on an `internal: true` network with **no route to a
   package index**;
3. the root filesystem is **read-only**.

Each is asserted in
[`tests/integration/test_device_constraints.py`](../tests/integration/test_device_constraints.py).
This is the ordinary situation for fielded hardware, and it is why
gateway-brokered migration is the realistic strategy rather than a contrivance:
you cannot upgrade the fleet, so you upgrade the hop you control.

## Link topology

The two links are **independent cryptographic contexts**. The gateway decrypts a
frame from the device and re-encrypts it under a separate upstream session
rather than forwarding the original bytes. That separation is what allows one
link to be modernized while the other cannot be touched.

```
edge network (internal: true)          backbone network
┌────────────────────────────┐   ┌──────────────────────────────┐
│ legacy-device → tap-edge → gateway → tap-backbone → cloud     │
│   LEGACY-RSA2048-OAEP-AESGCM  │  MLKEM768-X25519-HKDF-AESGCM  │
└────────────────────────────┘   └──────────────────────────────┘
```

The gateway straddles both networks. The device can reach the edge tap and
nothing else.

## Package boundaries

The device installs the same packages the modern services do, which forces a
constraint worth stating: `pqcwire` and `pqcnode` are **standard library only
and Python 3.9 compatible**, because the device imports them. All cryptography
lives in `pqcsuite`, whose hybrid module raises `CapabilityError` when used on a
backend without ML-KEM instead of failing at import.

That degradation is deliberate. The device imports everything, reports
`mlkem_available=False` at startup, advertises only the legacy suite, and logs
that the gateway must broker on its behalf. The limitation is a queryable
property rather than a crash. CI gates the 3.9 constraint, since modern syntax
slipping into those packages is the easiest way to break it by accident.

## Request flow

1. Device fetches the gateway's RSA public key, retrying with backoff — container
   start order should not decide whether the stack works.
2. Device wraps a fresh 32-byte secret under that key and posts the handshake.
3. Gateway accepts it, then opens its **own** upstream session. With
   `UPSTREAM_SUITE=hybrid` it fetches a signed ephemeral offer from the cloud,
   verifies the ML-DSA signature against a locally mounted public-key pin, and
   encapsulates to it. It never learns trust from `/pqc/identity`.
4. Each reading: device seals, gateway opens, gateway re-seals under the upstream
   session, cloud opens and persists.
5. Both taps record every frame in passing.

## Configuration as the migration switch

Suite selection is configuration, not code. `UPSTREAM_SUITE` defaults to
`hybrid`. The old `auto` value remains accepted only as a fail-closed alias for
`hybrid`: it makes no capability request and never selects the legacy suite.
Rollback must be an explicit local choice of `UPSTREAM_SUITE=legacy`; an
unauthenticated peer cannot trigger it. Both `hybrid` and `auto` require
`CLOUD_IDENTITY_PUBLIC_KEY_PATH` to name a valid out-of-band ML-DSA public key
and fail startup when local ML-KEM support is absent.

The modern Compose deployment creates the key pair in a networkless one-shot
provisioner, keeps private and public material in separate volumes, and mounts
each read-only into the cloud and gateway respectively. A missing, unreadable,
or malformed pin prevents gateway startup. `ALLOW_LEGACY_SUITE=false` on the
cloud completes the migration by refusing quantum-vulnerable traffic outright,
and the refusal is visible in logs and metrics rather than silent.
