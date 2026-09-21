# Architecture

## Components

| Service | Runtime | Role |
|---|---|---|
| `legacy-device` | Python 3.9, cryptography 3.4.8 | Replays 366 daily weather readings. Frozen firmware: 48 MB, 0.1 CPU, read-only rootfs, no route off the edge network. Uses `urllib.request` rather than an HTTP client package. |
| `gateway` | Python 3.12, cryptography 50 | Terminates the device's legacy session and opens a separate post-quantum session to the cloud. The broker. |
| `cloud` | Python 3.12, FastAPI, SQLite | Accepts either suite, persists readings, exposes a query API, health probes, and metrics. Can refuse the legacy suite by policy. |
| `tap` | Python 3.12 | Bounded teaching wiretap on each link. Relays normal protocol traffic and appends to a capped JSON Lines capture. |
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
3. Gateway accepts it only if its session identifier is neither active nor in
   the bounded recent-use history, then opens its **own** upstream session.
4. With `UPSTREAM_SUITE=hybrid` it fetches a signed ephemeral offer from the
   cloud, verifies ML-DSA against a locally mounted cloud pin, encapsulates, and
   signs the complete request transcript with its separately mounted ML-DSA
   identity. The cloud verifies that signature against its gateway pin before
   consuming the single-use offer. Neither side discovers trust over HTTP.
5. Each reading: device seals, gateway opens, gateway re-seals under the upstream
   session, cloud opens and persists. Local age/count exhaustion or gateway HTTP
   409 causes one fresh device handshake and one retry of the current reading.
6. Both taps record each in-bounds frame while capture storage remains available.

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

## Bounds and service state

Active sessions, recently used identifiers, and pending hybrid offers all have
separate time and count bounds. Wire session identifiers are exactly 16
lowercase hexadecimal characters. An identifier cannot replace an existing
entry; after expiry, eviction, or drop it remains blocked for the recent-use
TTL. An unexpired replay marker is never evicted to admit new state: a full
history fails new handshakes closed until TTL cleanup. These structures are
in-memory and per process. Restarting a service clears both sessions and replay
history, so a captured legacy handshake can be accepted again after restart;
clients also have to establish fresh sessions. Persistent distributed replay
state is intentionally not introduced in this PoC.

The cloud rejects new offers with HTTP 503 when `MAX_PENDING_OFFERS` is reached;
expiry or a successfully authenticated use releases capacity. Session-history
saturation also returns bounded HTTP 503. Record sessions enforce age and
record-count ceilings on both sealing and opening. Gateway upstream responses
reject compression before decoding and are body-size bounded. GET retries have
bounded per-attempt timeout, total deadline, count, and exponential backoff.
POSTs are not retried because offers, handshakes, and sequence numbers are
single-use. The in-path tap independently caps request and response bytes,
wall-clock relay duration, captured fields, and capture-file growth; direct
development ports bind only to `127.0.0.1`.

`/healthz` is process liveness. Gateway `/readyz` additionally checks that its
already validated local suite/identity configuration can reach the configured
cloud readiness endpoint. That reachability response is not a new trust root;
only the pinned keys authenticate handshakes.
