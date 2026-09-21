#!/usr/bin/env python3
"""A small local web page showing what happens in the backend.

Same live run as scripts/visualize.py -- real device, gateway and cloud apps
in-process with every HTTP call tapped -- rendered as a page instead of a
terminal dump. Every number comes from `collect_trace`, which both front-ends
share, so the page and the CLI cannot disagree.

    python scripts/visualize_web.py                 # http://127.0.0.1:8420
    python scripts/visualize_web.py --port 9000
    python scripts/visualize_web.py --no-browser

If the port is already taken the server moves to a free one and says so, rather
than dying on startup or leaving the browser on whatever else is listening.

Binds to 127.0.0.1 only. It runs handshakes with development keys and prints
byte counts; it is a local diagnostic, not something to expose.
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import socket
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

import uvicorn  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse  # noqa: E402
from visualize import KeySchedule, Probe, collect_trace  # noqa: E402

# ---------------------------------------------------------------------- style

CSS = """
:root {
  --bg: #0d1117; --panel: #161b22; --panel2: #1c2128; --line: #30363d;
  --text: #e6edf3; --dim: #8b949e;
  --pq: #3fb950; --legacy: #f85149; --warn: #d29922; --accent: #58a6ff;
  --mono: ui-monospace, "Cascadia Code", "Consolas", monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif;
}
.wrap { max-width: 1000px; margin: 0 auto; padding: 32px 16px 80px; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.02em; }
h2 { font-size: 18px; margin: 0 0 2px; }
.sub { color: var(--dim); font-size: 14px; margin: 0 0 28px; }
.card {
  background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 20px; margin: 0 0 18px;
}
.step { color: var(--accent); font: 600 12px/1 var(--mono); letter-spacing: .1em; }
.note { color: var(--dim); font-size: 13.5px; margin: 14px 0 0; }
.note b { color: var(--text); font-weight: 600; }
code, .mono { font-family: var(--mono); font-size: 13px; }

table { width: 100%; border-collapse: collapse; margin: 12px 0 0; }
td { padding: 6px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
td.k { color: var(--dim); width: 44%; font-size: 13.5px; }
td.v { font-family: var(--mono); font-size: 13px; }

.tag { display: inline-block; padding: 1px 8px; border-radius: 20px;
       font: 600 11px/1.7 var(--mono); }
.pq   { background: rgba(63,185,80,.15);  color: var(--pq);
        border: 1px solid rgba(63,185,80,.4); }
.bad  { background: rgba(248,81,73,.13);  color: var(--legacy);
        border: 1px solid rgba(248,81,73,.4); }

/* pipeline */
.pipe { display: flex; align-items: stretch; gap: 0; flex-wrap: wrap; margin: 6px 0 0; }
.node { flex: 1 1 130px; background: var(--panel2); border: 1px solid var(--line);
        border-radius: 8px; padding: 12px 10px; text-align: center; min-width: 120px; }
.node .name { font: 600 14px/1.3 var(--mono); }
.node .role { color: var(--dim); font-size: 11.5px; margin-top: 3px; }
.hop { flex: 0 1 150px; padding: 10px 6px; text-align: center; align-self: center;
       min-width: 120px; }
.hop .arrow { font-family: var(--mono); font-size: 13px; }
.hop .label { font: 600 11px/1.5 var(--mono); letter-spacing: .04em; }
.hop .detail { color: var(--dim); font-size: 11px; line-height: 1.45; margin-top: 2px; }
.hop.h1 .arrow, .hop.h1 .label { color: var(--legacy); }
.hop.h2 .arrow, .hop.h2 .label { color: var(--pq); }

/* bars */
.bars { margin: 14px 0 0; }
.bar { display: flex; align-items: center; gap: 10px; margin: 0 0 6px; }
.bar .bl { width: 190px; color: var(--dim); font-size: 12.5px; text-align: right;
           flex: 0 0 auto; }
.bar .track { flex: 1; background: var(--panel2); border-radius: 3px; height: 18px;
              overflow: hidden; }
.bar .fill { height: 100%; border-radius: 3px; }
.bar .bv { width: 78px; font-family: var(--mono); font-size: 12px; flex: 0 0 auto; }

/* flow */
.flow { border-left: 2px solid var(--line); margin: 12px 0 0 8px; padding: 0 0 0 18px; }
.flow .row { position: relative; padding: 9px 0; }
.flow .row::before { content: ""; position: absolute; left: -24px; top: 15px;
  width: 9px; height: 9px; border-radius: 50%; background: var(--line); }
.flow .row.pqok::before { background: var(--pq); }
.flow .row.legacy::before { background: var(--legacy); }
.flow .who { font: 600 13px/1.5 var(--mono); }
.flow .what { color: var(--dim); font-size: 13px; }

/* tiles */
.tiles { display: flex; gap: 12px; flex-wrap: wrap; margin: 6px 0 0; }
.tile { flex: 1 1 150px; background: var(--panel2); border: 1px solid var(--line);
        border-radius: 8px; padding: 14px; min-width: 140px; }
.tile .n { font: 600 24px/1.2 var(--mono); }
.tile .l { color: var(--dim); font-size: 12px; margin-top: 2px; }

pre.hex { background: var(--panel2); border: 1px solid var(--line); border-radius: 6px;
  padding: 12px; overflow-x: auto; font-family: var(--mono); font-size: 12px;
  color: var(--dim); margin: 10px 0 0; }

.verdict { display: flex; gap: 12px; flex-wrap: wrap; margin: 0 0 18px; }
.v { flex: 1 1 260px; border-radius: 10px; padding: 16px 18px; border: 1px solid; }
.v.good { background: rgba(63,185,80,.07); border-color: rgba(63,185,80,.35); }
.v.risk { background: rgba(248,81,73,.06); border-color: rgba(248,81,73,.32); }
.v h3 { margin: 0 0 4px; font-size: 15px; }
.v p { margin: 0; font-size: 13.5px; color: var(--dim); }

.btn { display: inline-block; background: var(--panel2); color: var(--text);
  border: 1px solid var(--line); border-radius: 6px; padding: 7px 14px;
  text-decoration: none; font-size: 13.5px; }
.btn:hover { border-color: var(--accent); color: var(--accent); }
.foot { color: var(--dim); font-size: 13px; margin-top: 28px; }
.foot a { color: var(--accent); }
"""


# ----------------------------------------------------------------- components


def esc(value: Any) -> str:
    return html.escape(str(value))


def rows(pairs: list[tuple[str, str]]) -> str:
    body = "".join(
        f'<tr><td class="k">{esc(k)}</td><td class="v">{v}</td></tr>' for k, v in pairs
    )
    return f"<table>{body}</table>"


def tag(text: str, kind: str) -> str:
    return f'<span class="tag {kind}">{esc(text)}</span>'


def bar(label: str, value: int, biggest: int, colour: str, unit: str = "B") -> str:
    pct = (value / biggest * 100) if biggest else 0
    return (
        f'<div class="bar"><div class="bl">{esc(label)}</div>'
        f'<div class="track"><div class="fill" style="width:{pct:.1f}%;'
        f'background:{colour}"></div></div>'
        f'<div class="bv">{value} {unit}</div></div>'
    )


def pipeline() -> str:
    return f"""
<div class="pipe">
  <div class="node"><div class="name">device</div>
    <div class="role">legacy sensor<br>non-upgradeable</div></div>
  <div class="hop h1">
    <div class="label">hop 1</div><div class="arrow">&#8212;&#8212;&gt;</div>
    <div class="detail">ECDH P-256<br>static-static<br>{tag('CLASSICAL', 'bad')}</div>
  </div>
  <div class="node"><div class="name">gateway</div>
    <div class="role">edge<br>trust boundary</div></div>
  <div class="hop h2">
    <div class="label">hop 2</div><div class="arrow">&#8212;&#8212;&gt;</div>
    <div class="detail">X25519 +<br>ML-KEM-768<br>{tag('POST-QUANTUM', 'pq')}</div>
  </div>
  <div class="node"><div class="name">cloud</div>
    <div class="role">store + read API</div></div>
</div>
<p class="note">The gateway is the migration seam: it <b>decrypts</b> hop 1 and
<b>re-encrypts</b> onto hop 2. That is why the device never has to change &mdash;
and also why the gateway is the one place that sees plaintext.</p>
"""


def card(step: str, title: str, body: str) -> str:
    return (
        f'<div class="card"><div class="step">STEP {esc(step)}</div>'
        f"<h2>{esc(title)}</h2>{body}</div>"
    )


# --------------------------------------------------------------------- blocks


def block_data(t: dict[str, Any]) -> str:
    station = t["station"]
    first = t["first_reading"]
    return card("1", "The data going in", rows([
        ("source file", "<code>data/weather_data.csv</code>"),
        ("station", f"lat {station['lat']}, lon {station['lon']} &middot; {esc(station['tz'])}"),
        ("readings parsed", f"{t['readings_parsed']} daily records"),
        ("first record", f"{esc(first['date'])} &middot; max {first['temp_max_c']} C "
                         f"&middot; min {first['temp_min_c']} C &middot; "
                         f"{first['precip_mm']} mm &middot; {first['wind_max_kmh']} km/h"),
    ]) + '<p class="note">Public Open-Meteo observations &mdash; there is no secret '
        "here. The point is the migration mechanics, not the confidentiality of "
        "this particular data.</p>")


def block_hop1(t: dict[str, Any]) -> str:
    h = t["hop1_handshake"]
    body = rows([
        ("protocol", esc(h["protocol"])),
        ("ClientHello", f"POST /handshake &middot; {h['req_bytes']} bytes"),
        ("client_nonce", f"{h['client_nonce_len']} random bytes"),
        ("ServerHello", f"HTTP {h['status']} &middot; {h['resp_bytes']} bytes"),
        ("session_id / nonce_prefix",
         f"{h['session_id_len']} B / {h['nonce_prefix_len']} B"),
        ("expires_at", esc(h["expires_at"])),
        ("ServerHello signature", tag("NONE", "bad")),
    ])
    body += """
<p class="note"><b>Key derivation.</b> <code>Z = ECDH(device_static, gateway_static)</code>
then <code>key = HKDF-SHA256(Z, salt=nonces, info=label)</code>.</p>
<p class="note"><b>Two deliberate legacy weaknesses, both visible above.</b>
No ephemeral key, so every session this device ever opens derives from the
<b>same Z</b> &mdash; one recovered static key retroactively opens all of them.
And the ServerHello carries no signature, so an on-path attacker can forge it;
the device only finds out when its first message is rejected.</p>
<p class="note">This hop is frozen on purpose. The premise is that the firmware
cannot be updated &mdash; it is the &ldquo;before&rdquo; state being migrated away from.</p>
"""
    return card("2", "hop 1 handshake — device to gateway (the legacy hop)", body)


def block_hop2(t: dict[str, Any]) -> str:
    h = t["hop2_handshake"]
    shares = h["key_shares"]
    suite_tag = tag(h["selected_suite"], "pq" if h["is_pqc"] else "bad")

    share_rows = []
    for name, parts in shares.items():
        detail = ", ".join(f"{k} {v} B" for k, v in parts.items())
        share_rows.append((f"key_share[{name}]", esc(detail)))

    body = rows([
        ("protocol", esc(h["protocol"])),
        ("ClientHello", f"POST /handshake &middot; {h['req_bytes']} bytes"),
        ("offered_suites", ", ".join(esc(s) for s in h["offered_suites"])),
        *share_rows,
        ("client signature", f"{h['client_sig_len']} B ECDSA P-256 over the "
                             f"<b>whole offer</b>"),
        ("ServerHello", f"HTTP {h['status']} &middot; {h['resp_bytes']} bytes"),
        ("selected_suite", suite_tag),
        ("mlkem768_ct", f"{h['mlkem768_ct_len']} bytes (ML-KEM-768 encapsulation)"),
        ("x25519_pub", f"{h['x25519_pub_len']} bytes"),
        ("server signature", f"{h['server_sig_len']} B over the full transcript"),
    ])

    biggest = max([h["mlkem768_ct_len"], *(v for p in shares.values() for v in p.values())])
    bars = ['<div class="bars">']
    for name, parts in shares.items():
        for k, v in parts.items():
            colour = "var(--pq)" if "mlkem" in k or "x25519" in k else "var(--legacy)"
            bars.append(bar(f"{name.split('-')[0]} / {k}", v, biggest, colour))
    bars.append(bar("server mlkem768_ct", h["mlkem768_ct_len"], biggest, "var(--pq)"))
    bars.append(bar("client signature", h["client_sig_len"], biggest, "var(--dim)"))
    bars.append("</div>")

    body += "".join(bars)
    body += f"""
<p class="note"><b>What just happened, in order.</b></p>
<div class="flow">
  <div class="row"><span class="who">gateway</span>
    <span class="what">&mdash; generated an <b>ephemeral</b> X25519 key and an
    <b>ephemeral</b> ML-KEM-768 keypair, offered both suites, signed the entire offer</span></div>
  <div class="row"><span class="who">cloud</span>
    <span class="what">&mdash; verified that signature, then chose a suite under
    its policy</span></div>
  <div class="row pqok"><span class="who">cloud</span>
    <span class="what">&mdash; encapsulated to the gateway's ML-KEM key &rarr;
    (shared_secret, {h['mlkem768_ct_len']} B ciphertext), and signed a transcript that
    <b>re-includes the gateway's whole offer</b></span></div>
  <div class="row pqok"><span class="who">gateway</span>
    <span class="what">&mdash; verified that signature against the offer it actually
    <b>sent</b>. An attacker who edited the offer in flight cannot survive this check.</span></div>
  <div class="row pqok"><span class="who">both sides</span>
    <span class="what">&mdash; ran the same combiner:
    <code>IKM = ss_mlkem768 (32 B) || ss_x25519 (32 B)</code></span></div>
</div>
<p class="note"><b>The security claim:</b> this key is safe if <b>either</b>
ML-KEM-768 or X25519 holds. A quantum attacker must break both, and only ML-KEM is
believed to resist one. ML-KEM establishes the key and <b>never touches the
payload</b> &mdash; which is why the per-message cost below is zero.</p>
"""
    return card("3", "hop 2 handshake — gateway to cloud (the post-quantum one)", body)


def block_keys(t: dict[str, Any]) -> str:
    k: KeySchedule = t["key_schedule"]
    body = rows([
        ("ML-KEM-768 shared secret", f"{k.ss_mlkem_len} bytes &middot; "
                                     f"<i>never printed</i>"),
        ("X25519 shared secret", f"{k.ss_x25519_len} bytes &middot; <i>never printed</i>"),
        ("nonce_prefix", f"{k.nonce_prefix_len} bytes, <b>shared</b> by both directions"),
        ("key_c2s (gw-&gt;cloud)", f"fingerprint <code>{esc(k.fp_c2s)}</code>"),
        ("key_s2c (cloud-&gt;gw)", f"fingerprint <code>{esc(k.fp_s2c)}</code>"),
        ("keys differ", tag("YES", "pq") if k.differ else tag("NO", "bad")),
    ])
    body += """
<p class="note">Fingerprints are truncated SHA-256 &mdash; one-way, and shown only
to prove the two keys differ. The keys themselves are never printed or logged.</p>
<p class="note"><b>Why it matters.</b> The nonce is <code>nonce_prefix || counter</code>,
both directions share the prefix, and both start counting at 0. If they also shared
a <b>key</b>, message 0 each way would reuse the same (key, nonce) pair &mdash; the
one thing AES-GCM must never do. Separate HKDF labels make that impossible by
construction rather than by convention.</p>
"""
    return card("4", "Why the two directions get different keys", body)


def block_message(t: dict[str, Any]) -> str:
    m = t["message"]
    biggest = max(m["hop1_req_bytes"], m["hop2_req_bytes"], t["plaintext_len"])
    body = f"""
<div class="flow">
  <div class="row"><span class="who">device</span>
    <span class="what">&mdash; builds the reading JSON, {t['plaintext_len']} bytes plaintext,
    then AES-256-GCM seals it (nonce = prefix||counter, aad = session_id||counter)</span></div>
  <div class="row legacy"><span class="who">&rarr; gateway</span>
    <span class="what">POST /ingest &middot; {m['hop1_req_bytes']} bytes &middot;
    HTTP {m['hop1_status']} {tag('accepted', 'pq')}</span></div>
  <div class="row"><span class="who">gateway</span>
    <span class="what">&mdash; opens the AEAD, validates plausibility bounds, checks the
    payload device_id matches the session, wraps it in an envelope and
    <b>re-encrypts onto hop 2</b></span></div>
  <div class="row pqok"><span class="who">&rarr; cloud</span>
    <span class="what">POST /ingest &middot; {m['hop2_req_bytes']} bytes &middot;
    HTTP {m['hop2_status']} {tag('accepted', 'pq')}</span></div>
  <div class="row pqok"><span class="who">cloud</span>
    <span class="what">&mdash; opens the AEAD, validates again, writes to SQLite</span></div>
</div>
<div class="bars">
  {bar('plaintext reading', t['plaintext_len'], biggest, 'var(--dim)')}
  {bar('hop 1 ciphertext', m['hop1_ct_bytes'], biggest, 'var(--legacy)')}
  {bar('hop 1 request', m['hop1_req_bytes'], biggest, 'var(--legacy)')}
  {bar('hop 2 ciphertext', m['hop2_ct_bytes'], biggest, 'var(--pq)')}
  {bar('hop 2 request', m['hop2_req_bytes'], biggest, 'var(--pq)')}
</div>
<p class="note">Base64 inflates each request by roughly a third over the raw
ciphertext. The <b>post-quantum cost per message is 0 bytes</b>: ML-KEM ran once
during the handshake and never touches a payload.</p>
<p class="note"><b>What an eavesdropper on hop 2 actually sees:</b></p>
<pre class="hex">{esc(m['ciphertext_hex'])}</pre>
<p class="note">Recorded today, that stays confidential against a future quantum
computer, because the key came from ML-KEM-768. <b>The same reading crossed hop 1
first, where it does not.</b></p>
"""
    return card("5", "One reading travelling end to end", body)


def block_probes(t: dict[str, Any]) -> str:
    probes: list[Probe] = t["probes"]
    body = "<table>"
    for p in probes:
        ok = p.status != 200
        body += (
            f'<tr><td class="k">{esc(p.label)}</td><td class="v">'
            f'{tag(f"HTTP {p.status} {p.reason}", "pq" if ok else "bad")}'
            f'<div style="color:var(--dim);font-size:12px;margin-top:3px">'
            f"{esc(p.note)}</div></td></tr>"
        )
    body += "</table>"
    body += """
<p class="note">Every one returns a 4xx with a reason. None raises, none returns
500, and none says more than a category. The <code>null session_id</code> case is
here because it once <b>did</b> return 500 &mdash; the negative tests found it and
<code>services/common/wire.py</code> was hardened rather than the call sites patched.</p>
<p class="note"><b>Note the two different rejections.</b> A flipped bit fails the
AEAD <b>tag</b>; a wrong counter fails the <b>replay</b> check before the tag is
ever examined. Getting a rejection is not enough &mdash; it has to be the right one.</p>
"""
    return card("6", "The backend refusing bad input (rejected, never crashed)", body)


def block_state(t: dict[str, Any]) -> str:
    stats, health = t["stats"], t["health"]
    pqc = stats.get("pqc", {})
    storage = stats.get("storage", {})
    messages = stats.get("messages", {})
    fraction = pqc.get("pqc_fraction")

    tiles = f"""
<div class="tiles">
  <div class="tile"><div class="n" style="color:var(--pq)">{esc(fraction)}</div>
    <div class="l">pqc_fraction</div></div>
  <div class="tile"><div class="n">{esc(storage.get('total'))}</div>
    <div class="l">readings in SQLite</div></div>
  <div class="tile"><div class="n" style="color:var(--pq)">
    {esc(pqc.get('handshakes_hybrid'))}</div><div class="l">hybrid handshakes</div></div>
  <div class="tile"><div class="n" style="color:var(--legacy)">
    {esc(pqc.get('handshakes_classical'))}</div>
    <div class="l">classical fallbacks</div></div>
</div>
"""
    body = tiles + rows([
        ("cloud status", tag(health.get("status", "?"), "pq")),
        ("protocols served", ", ".join(esc(p) for p in health.get("protocols", []))),
        ("policy", f"<code>{esc(health.get('policy'))}</code>"),
        ("date range", f"{esc(storage.get('first_date'))} .. {esc(storage.get('last_date'))}"),
        ("messages accepted / rejected",
         f"{messages.get('accepted')} / {messages.get('rejected')}"),
        ("downgrades refused", esc(pqc.get("handshakes_downgrade_refused"))),
    ])

    sample = t["readings_sample"][:3]
    if sample:
        lines = "\n".join(esc(json.dumps(r, separators=(",", ":"))[:110]) for r in sample)
        body += f'<p class="note"><b>GET /readings?limit=5</b></p><pre class="hex">{lines}</pre>'

    body += """
<p class="note"><b>pqc_fraction is the number to watch.</b> A health check
returning 200 proves the process started. It does not prove hop 2 negotiated
post-quantum crypto rather than quietly falling back to classical. That is exactly
what <code>scripts/smoke_test.py</code> asserts in CI, and it is the check that
fails on a stack which is otherwise completely healthy.</p>
"""
    return card("7", "What ends up in the cloud", body)


def verdict() -> str:
    return """
<div class="verdict">
  <div class="v good"><h3>hop 2 is post-quantum</h3>
    <p>Gateway&nbsp;&rarr;&nbsp;cloud traffic recorded today stays confidential
    against a future quantum computer. Harvest-now-decrypt-later protection holds.</p></div>
  <div class="v risk"><h3>the system as a whole is not</h3>
    <p>Hop&nbsp;1 is classical and cannot change &mdash; the device is
    non-upgradeable by premise. Authentication on both hops is still ECDSA P-256,
    which a CRQC also breaks; that enables <b>active</b> attacks only.</p></div>
</div>
"""


def render(t: dict[str, Any]) -> str:
    blocks = "".join([
        block_data(t), block_hop1(t), block_hop2(t), block_keys(t),
        block_message(t), block_probes(t), block_state(t),
    ])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Backend trace &mdash; mlkem-modernize</title><style>{CSS}</style></head>
<body><div class="wrap">
  <h1>What actually happens in the backend</h1>
  <p class="sub">Real device, gateway and cloud services run in-process with every
  HTTP call tapped. Every number below was measured from this run &mdash; nothing
  is quoted from the docs.</p>
  {verdict()}
  <div class="card"><h2>The pipeline</h2>{pipeline()}</div>
  {blocks}
  <p class="foot">
    <a class="btn" href="/?run=1">Run it again</a>
    &nbsp; <a href="/api/trace">raw JSON</a>
    &nbsp;&middot;&nbsp; terminal version: <code>python scripts/visualize.py</code>
    &nbsp;&middot;&nbsp; full detail in <code>docs/ARCHITECTURE.md</code> and
    <code>docs/MIGRATION.md</code>
  </p>
</div></body></html>"""


# ------------------------------------------------------------------------ app


def create_app(keys_dir: Path, data_file: Path) -> FastAPI:
    app = FastAPI(title="mlkem-modernize backend trace")
    cache: dict[str, Any] = {}
    lock = threading.Lock()

    def trace(force: bool = False) -> dict[str, Any]:
        # One stack at a time: each run builds real services and a fresh DB.
        with lock:
            if force or "t" not in cache:
                cache["t"] = collect_trace(keys_dir, data_file)
            return dict(cache["t"])

    @app.get("/", response_class=HTMLResponse)
    def index(run: int = 0) -> HTMLResponse:
        return HTMLResponse(render(trace(force=bool(run))))

    @app.get("/api/trace")
    def api_trace(run: int = 0) -> JSONResponse:
        t = trace(force=bool(run))
        # Dataclasses are not JSON-serialisable; flatten the two that appear.
        t["key_schedule"] = vars(t["key_schedule"])
        t["probes"] = [vars(p) for p in t["probes"]]
        return JSONResponse(t)

    return app


DEFAULT_PORT = 8420


def port_is_free(port: int) -> bool:
    """True if we can actually listen on 127.0.0.1:port right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def pick_port(preferred: int) -> int:
    """Return a port we can bind, falling back to one the OS picks.

    Without this, a port already owned by something else (8080 is a popular
    choice -- pgAdmin, Jenkins, Tomcat) either kills the server on startup or,
    worse, leaves the browser showing that OTHER service's page while this one
    is not running at all. Failing loudly beats a confusing blank page.
    """
    if port_is_free(preferred):
        return preferred

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        chosen = int(sock.getsockname()[1])

    print(f"note: port {preferred} is already in use by something else; "
          f"using {chosen} instead")
    return chosen


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--keys-dir", default="keys")
    parser.add_argument("--data", default="data/weather_data.csv")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open a browser window")
    args = parser.parse_args()

    keys_dir = Path(args.keys_dir)
    if not (keys_dir / "gateway_ecdsa_priv.pem").exists():
        print(f"error: no keys in {keys_dir.resolve()}", file=sys.stderr)
        print("  run: python scripts/gen_keys.py --out keys", file=sys.stderr)
        return 1

    data_file = Path(args.data)
    if not data_file.exists():
        print(f"error: no weather data at {data_file.resolve()}", file=sys.stderr)
        return 1

    # The traced services log for themselves; the page narrates instead.
    logging.getLogger().setLevel(logging.ERROR)
    for name in ("cloud", "gateway", "device", "httpx"):
        logging.getLogger(name).setLevel(logging.ERROR)

    port = pick_port(args.port)
    url = f"http://127.0.0.1:{port}"
    print(f"backend trace on {url}   (ctrl-c to stop)")
    if not args.no_browser:
        # Give uvicorn a moment to bind, so the browser does not race it.
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    # 127.0.0.1, never 0.0.0.0: this runs handshakes with development keys.
    uvicorn.run(create_app(keys_dir, data_file), host="127.0.0.1",
                port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
