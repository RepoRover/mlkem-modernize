# Migration Strategy: Classical → Post-Quantum

How this system moves from classical key establishment to hybrid
X25519 + ML-KEM-768, given a device fleet that cannot be upgraded.

**Current state: Phase 1 complete.** Hop 2 (gateway → cloud) does hybrid PQC
with suite negotiation and downgrade protection. Hop 1 (device → gateway) is
unchanged and classical.

Run `python scripts/demo_phases.py` to see each phase execute.

---

## 1. What is and is not protected today

This is the section to read if you read nothing else.

| Path | Key establishment | Post-quantum? |
|---|---|---|
| device → gateway | static-static ECDH P-256 | **No** |
| gateway → cloud | X25519 + ML-KEM-768 | **Yes** |
| authentication (both hops) | ECDSA P-256 | **No** |

**The system as a whole is not post-quantum secure.** Hop 2 is. An attacker who
records **hop 1** traffic today can decrypt it once a cryptographically relevant
quantum computer (CRQC) exists, and nothing on hop 2 changes that. What Phase 1
bought is protection for the gateway→cloud link, which is the one that crosses
the public internet and is therefore the one most plausibly being recorded.

---

## 2. What the ECDSA weakness does and does not mean

ECDSA P-256 is quantum-broken, and it is still what authenticates both peers and
underwrites downgrade protection. It is easy to overstate or understate what
that costs, so precisely:

### Recorded hybrid traffic stays confidential (HNDL protection holds)

A session key on hop 2 is derived from `ss_mlkem768 ‖ ss_x25519`. Breaking
ECDSA does not reveal either secret. An attacker who captures hybrid traffic
today and acquires a CRQC in 2035 still has to break **ML-KEM-768** to decrypt
it — signatures are irrelevant to confidentiality after the fact.

**Harvest-now-decrypt-later protection on hop 2 is real and it holds.** That is
the entire point of doing this work now rather than when a CRQC appears.

### ECDSA's weakness enables ACTIVE attacks, and only once a CRQC exists

With a CRQC an attacker can forge ECDSA signatures, and can therefore, **in real
time, during a handshake**:

- impersonate the gateway to the cloud, or the cloud to the gateway;
- rewrite `offered_suites` and produce a matching signature, forcing the
  classical suite;
- man-in-the-middle a session and read it as it happens.

All of these require the attacker to be **on the path at the moment of the
handshake**, with a CRQC already in hand. None of them retroactively decrypt a
session recorded before the CRQC existed.

### The practical consequence

| Attacker capability | Hybrid session recorded **before** CRQC | New session **after** CRQC |
|---|---|---|
| Passive recording | **Safe** — needs ML-KEM broken | Safe |
| Active MITM with CRQC | **Safe** — already recorded | **Compromised** — ECDSA forged |

So the migration is worth doing now, and it is **not finished**. Closing the
active-attack gap needs ML-DSA (FIPS 204) for authentication, which is out of
scope for this project and recorded as remaining risk W3.

One more thing the policy control buys: even with forged signatures, a cloud on
`PQC_POLICY=require` will not *complete* a classical session. Forging the
signature gets an attacker a refused handshake, not a downgraded one. That
defence is configuration, not cryptography, but it is the one that survives a
CRQC.

---

## 3. Phases

| Phase | Hop 1 | Hop 2 cloud policy | Hop 2 gateway policy | Status |
|---|---|---|---|---|
| 0 | classical | — | — | done (Phase 2 of the project) |
| 1 | classical | `prefer` | `prefer` | **done** |
| 2 | classical | `require` | `require` | ready — flip the env var |
| 3 | dual-stack | `require` | `require` | future work |
| 4 | hybrid | `require` | `require` | future work |

Defaults as shipped: cloud `require`, gateway `prefer`. A freshly started stack
is therefore already PQC-only, while the phases remain demonstrable by changing
`CLOUD_PQC_POLICY` / `GATEWAY_PQC_POLICY`.

### Phase 1 — hybrid available, observe

Both services understand `wx-hybrid/2`. With `prefer` on both sides, upgraded
peers negotiate hybrid and legacy peers keep working while being logged and
counted.

```bash
CLOUD_PQC_POLICY=prefer GATEWAY_PQC_POLICY=prefer docker compose up --build
curl -s http://127.0.0.1:8000/stats | python -m json.tool
```

Watch `pqc.pqc_fraction`. **Exit criterion: `pqc_fraction == 1.0` sustained for
7 days**, with `handshakes_classical` flat at zero over the same window.

### Phase 2 — require PQC

```bash
CLOUD_PQC_POLICY=require GATEWAY_PQC_POLICY=require docker compose up --build
```

The cloud refuses classical-only peers with `403 downgrade_refused`. Legacy
`wx-legacy/1` gateways stop working — that is the forcing function, not an
outage to be patched around.

**Exit criterion: `handshakes_downgrade_refused == 0` for 7 days**, proving no
un-upgraded gateway is still trying.

**Rollback:** set `CLOUD_PQC_POLICY=prefer`. Reverting to `classical-only` is
possible but logs a startup banner and should require sign-off.

### Phase 3 — upgraded devices negotiate PQC on hop 1

Requires new firmware, so it depends on a hardware refresh cycle rather than on
us. The design carries over unchanged: an upgraded device sends
`offered_suites` in its hop 1 ClientHello, and the gateway runs the same
`negotiate()` under a separate `HOP1_PQC_POLICY`.

Both fleets are served from one endpoint because negotiation is per-handshake,
so old and new devices coexist indefinitely.

What hop 1 also needs fixing while the firmware is open — these are the Phase-2
weaknesses that a new device should not inherit:

- ephemeral keys, so the hop gains forward secrecy (W4);
- an authenticated ServerHello (W5);
- full transcript binding in the KDF (W6);
- per-direction keys if responses ever become encrypted.

### Phase 4 — sunset classical

Delete the classical code paths and the `classical-only` policy value.

---

## 4. Sunset criteria for classical

Measurable, not a judgement call. **All** must hold:

| # | Criterion | How it is checked |
|---|---|---|
| 1 | Zero classical handshakes for 30 consecutive days | `pqc.handshakes_classical` on `/stats` |
| 2 | Zero downgrade refusals for 30 days | `pqc.handshakes_downgrade_refused` |
| 3 | Every device reports PQC-capable firmware | device inventory (does not exist yet — see §6) |
| 4 | A 30-day rollback window has elapsed since Phase 2 | change log |
| 5 | ML-DSA decision recorded | either implemented, or accepted as residual risk in writing |

Criterion 5 is deliberate. Removing the classical *key exchange* while leaving
classical *signatures* is a half-migration, and shipping it without a written
decision would let the gap be forgotten.

**Criterion 3 cannot currently be satisfied.** There is no device inventory and
no firmware-version reporting. Building one is a prerequisite for Phase 4, not
an afterthought.

---

## 5. The gateway as trust boundary

The biggest architectural risk, stated plainly.

The gateway **decrypts hop 1 and re-encrypts for hop 2**. It is not a relay; it
is a point where plaintext readings exist in memory. This is exactly what makes
a staged migration possible — the device never changes — and exactly what limits
what the migration achieves.

### What this costs

1. **No end-to-end confidentiality.** Readings are protected device→gateway and
   gateway→cloud, never device→cloud. Hop 2's post-quantum protection stops at
   the gateway's memory.
2. **Compromising the gateway defeats everything.** An attacker there reads all
   plaintext and can fabricate readings the cloud accepts as device-authenticated
   — the cloud has no independent way to verify hop 1 happened (W8).
3. **The weakest hop sets the real security level.** Hop 1 is static-static ECDH
   with no forward secrecy. An attacker recording hop 1 and later obtaining
   either static key recovers *every* session key that device ever used. Hop 2
   being post-quantum does not help.
4. **The gateway holds keys for both hops**, so it is a single point of
   compromise for the whole path.
5. **It is a single point of failure.** No store-and-forward: if the cloud is
   unreachable, readings are dropped (W13).

### Why it is still the right structure here

The device is non-upgradeable by premise. The alternatives are worse:

- *Wait for a hardware refresh* — leaves the internet-facing hop classical for
  years while HNDL recording continues.
- *End-to-end PQC device→cloud* — requires the device to change, which is the
  one thing that cannot happen.
- *Tunnel hop 1 inside hop 2* — the gateway still terminates hop 1; identical
  trust boundary with more moving parts.

The honest framing: **this migration protects the internet-facing hop and buys
time.** It does not make the system post-quantum. Anyone presenting this work
should say both sentences together.

### Mitigations worth doing before Phase 3

- Per-reading device signatures, so the cloud can verify hop 1 independently
  rather than trusting `device_hop.verified` (W8).
- Gateway key storage in an HSM or TPM rather than a shared volume (W11).
- Shorten hop 1 sessions to bound the data under any one derived key — though
  this cannot bound static-key compromise.

---

## 6. Risks and open items

| Risk | Impact | Status |
|---|---|---|
| ECDSA is quantum-broken | Active attacks post-CRQC; see §2 | **Accepted** — ML-DSA out of scope (W3) |
| Hop 1 classical | Recorded hop 1 traffic decryptable post-CRQC | **Accepted** until Phase 3 |
| Gateway sees plaintext | No end-to-end protection | **Accepted** — inherent to the design |
| No device inventory | Sunset criterion 3 unverifiable | **Open** — blocks Phase 4 |
| ML-KEM implementation not FIPS 140-3 validated | Cannot claim validated crypto | **Accepted** — see DECISIONS.md |
| Handshake size grew ~5.6× on hop 2 | More bandwidth per rekey | **Accepted** — measured, see §7 |
| Hybrid handshakes are fingerprintable | A ~4 KB handshake reveals the suite in use | **Accepted** — no traffic analysis protection anyway (W10) |

---

## 7. Measured cost

From `results/pqc-hybrid-latest.md`, 300 iterations, in-process.

| | Classical | Hybrid | Delta |
|---|---:|---:|---:|
| hop 2 key establishment (crypto only) | 0.746 ms | 1.158 ms | **+55%** |
| hop 2 handshake bytes | 710 B | 3959 B | **+458%** |
| per-message size | 416 B | 416 B | **0%** |

The per-message row is the one that matters most: **ML-KEM establishes a key and
never touches the payload**, exactly as `CLAUDE.md` requires. If that row ever
moves, the KEM has leaked onto the data path and something is badly wrong.

At the default rekey interval (100 records or 600 s), the extra ~3.2 KB per
handshake is amortised over 100 readings — roughly 32 bytes per reading, against
a 416-byte message. Negligible here; it would not be on a constrained radio
link, which is a reason to keep ML-KEM off hop 1 until the device design allows.
