# AI Usage Log

**Harness:** Pi

**Primary model:** `gpt-5.6-sol` (reasoning varied by task). Sessions 5 and 9 used `gpt-6-astra`.

Significant AI-assisted work on the `matheus` branch, organized by conversation in chronological order. Each entry pairs a user prompt with its outcome and file changes. Context summarizes the preceding question or proposal. Verification describes checks performed during the original work.

**Editorial note:** Quoted user prompts and answers are lightly edited for typos, grammar, punctuation, and filler words. Their meaning and substantive instructions are preserved; quotations are not strictly verbatim.

**File-change legend:** `+` added, `~` edited, `-` removed, `→` moved. Paths and markers describe the stage of work in that entry, not necessarily the final tree or a commit's status. Planning-only answers do not imply implementation changes. Untracked drafts are identified explicitly.

## Session 1 — Initial architecture, workspace, and tooling

### Read the assignment before planning

**User prompt**

> Study both PDFs in this repo. I'd like to create a plan for this; let me know when you've studied them.

**Outcome:** Read `project.pdf` and `SDMO_Project.pdf`, then inspected the repository. There was a weather dataset but no existing service implementation, so the following discussion established a greenfield simulation rather than a migration of supplied application code.

**Files modified:** None; document and repository review only.

### Define the starting point and planning scope

**Context:** The assistant asked whether starter code existed (Q1), whether planning should include the whole assignment or just the codebase (Q2), which report perspective to choose (Q3), and how the team was organized (Q4).

**User prompt**

> Q1. Everything is to be implemented from scratch (weather data will most likely be used).
> Q2. The plan scope should be the codebase only, including codebase documentation but not other reports, peer review, etc.
> Q3. Not relevant.
> Q4. Not relevant; outside the scope.

**Outcome:** Limited the plan to implementation and codebase documentation; reports, presentation planning, and team organization were outside this discussion. Established terminology for Device, Gateway, Cloud, and weather observations.

**Files modified**

- `+` `CONTEXT.md` — temporary, untracked domain glossary; no application code was created.

### Choose service boundaries, protected links, and storage

**Context:** Q6 asked about separate processes versus one application; Q7 asked which link should use ML-KEM; Q8 asked how to protect the legacy link; Q9 proposed Docker Compose and SQLite for persistence.

**User prompt**

> Q6. Each should be a separate program.
> Q7. The idea is that the legacy device cannot handle ML-KEM computation, so it should be gateway <=> cloud.
> Q8. Help me decide on something. As seen from the device, it should be secure with, for example, AES/ChaCha20.
> Q9. Docker would be a good idea for all programs; perhaps we could use Postgres as the cloud database.

**Outcome:** Chose independently running Device, Gateway, and Cloud programs, with ML-KEM restricted to Gateway ↔ Cloud and symmetric protection on the compatibility link. Preferred PostgreSQL over the proposed SQLite. The precise legacy cipher remained open.

**Files modified**

- `~` `CONTEXT.md` — distinguished the Device/Gateway compatibility path from the Gateway/Cloud modernized path.

### Settle the Device population and transmission pattern

**Context:** Q10 asked how many legacy devices to demonstrate; Q11–Q13 covered the ML-KEM session and how the Gateway should trust the Cloud key; Q14 asked how the Device should send data.

**User prompt**

> Q8. Why AES? Q10. One legacy device is enough. Q11. I don't know how ML-KEM works. Q12. Don't know. Q13. ??? Q14. I think the idea is that the device is sending data constantly, in a loop over certain times of the day perhaps, since it's weather data.

**Outcome:** Answered Q8 by explaining that AES-GCM and ChaCha20-Poly1305 are both authenticated encryption, and kept ChaCha20-Poly1305 for the software-only simulated Device. Scoped the demonstration to one explicitly identified Device without enrollment or fleet management. Explained that ML-KEM establishes a shared secret but neither encrypts the data nor authenticates the Cloud, so the Gateway would pin the Cloud public key and derive a symmetric key through HKDF. Because the dataset holds one row per day, chose a configurable send interval that loops after the final row rather than real-time daily replay. These choices later became the single-Device and continuous-replay requirements in Session 4.

**Files modified:** None at this step; the decisions fed the plan created below.

### Choose a network-capable legacy-device profile

**Context:** The assistant answered the user's Arduino suggestion with an Arduino Uno R3 and Ethernet shield. The user wanted a constrained device with networking built in.

**User prompts**

> We should pick a device to simulate (some sort of Arduino, perhaps).

> 2. We should ideally pick a device with a network card but not capable of running ML-KEM.

**Outcome:** Selected an ESP8266-inspired weather-station simulator. Described ML-KEM as operationally unsuitable under the assumed resource/network workload, not mathematically impossible. The simulation would model protocol and deployment behavior, not CPU instructions or real firmware.

**Files modified**

- `~` `CONTEXT.md` — changed the legacy-device definition to an ESP8266-based, network-capable weather station.

### Consolidate the plan in a monorepo

**Context:** The three services, wire protocol, integration tests, and deployment needed to evolve together.

**User prompt**

> Should this be a monorepo?

**Outcome:** Recommended one repository with separate programs/images and created a codebase plan covering architecture, trust boundaries, implementation phases, testing, deployment, and exclusions.

**Files modified**

- `+` `PLAN.md` — temporary, untracked implementation plan.
- `~` `CONTEXT.md` — finalized the weather-station vocabulary.

### Verify ML-KEM feasibility with throwaway code

**Context:** Before committing to a crypto library, the assistant proposed a small Docker experiment to generate a keypair, encapsulate/decapsulate a secret, and verify agreement.

**User prompt**

> Do it quickly; it should be throwaway code.

**Outcome:** Selected the standardized `cryptography==48.0.0` ML-KEM-768 API after a disposable-container test. The prototype was intentionally not retained.

**Files modified**

- `~` `PLAN.md` — replaced the pending crypto-spike step with the selected library and measured key/ciphertext sizes.

**Verification:** Both sides obtained the same 32-byte secret; the public key was 1,184 bytes and KEM ciphertext 1,088 bytes. No additional system packages were needed.

### Adopt uv and separate Docker deployments

**User prompt**

> We should use `uv` from Astral as the package manager. Docker should be used to simulate the hardware of the legacy device and gateway, and the cloud should also be encapsulated in Docker.

**Outcome:** Planned a uv workspace/shared lockfile and separate Device, Gateway, Cloud, and PostgreSQL containers. Explicitly distinguished container deployment/resource limits from faithful ESP8266 hardware emulation.

**Files modified**

- `~` `PLAN.md` — added uv workspace/lockfile requirements, per-service images, Compose deployment, and the emulation limitation. Dockerfiles were not implemented yet.

### Add repository checks

**User prompt — opening excerpt; illustrative YAML omitted**

> We should have pre-commit hooks for formatting/linting. Example:

**Outcome:** Created hook configuration for uv lock checking, Ruff linting/import sorting/formatting, and Pyright. The initial example versions were corrected in the next step, and the separate sorting/format hooks were dropped later in this session.

**Files modified**

- `+` `.pre-commit-config.yaml` — defined the requested hooks.
- `~` `PLAN.md` — added the hook-based quality checks.

### Correct the example dependency pins

**Context:** The assistant had copied the versions from the user's sample hook configuration without checking current tags.

**User prompt**

> Update the versions to the latest; don't blindly copy versions.

**Outcome:** Checked upstream tags rather than treating illustrative versions as requirements.

**Files modified**

- `~` `.pre-commit-config.yaml` — uv `0.8.0` → `0.12.17`, Ruff `v0.12.5` → `v0.16.8`, Pyright `v1.1.403` → `v1.1.414`.

### Require runtime validation

**User prompt**

> We should use Pydantic for runtime validations.

**Outcome:** Required Pydantic at CSV, environment-configuration, HTTP, and decrypted-message boundaries, while keeping internal values as ordinary Python types where appropriate.

**Files modified**

- `~` `PLAN.md` — added boundary-validation requirements and corresponding unit-test expectations. Service dependencies/models followed during implementation.

### Create empty service directories

**User prompt**

> Scaffold the repos. For now, each service should be just an empty directory.

**Outcome:** Created empty service directories without application code or package placeholders. Empty directories themselves would not be tracked by Git.

**Files/directories changed**

- `+` `services/device/`, `services/gateway/`, `services/cloud/` — empty directories only.

### Remove the extra service-directory level

**Context:** The initial empty directories were nested under `services/`.

**User prompt**

> Do we need to nest? Can't each service live at the root?

**Outcome:** Recommended root-level service directories; after the user's confirmation, moved them and removed the empty parent directory.

**Files/directories changed**

- `→` `services/device/` → `device/`; `services/gateway/` → `gateway/`; `services/cloud/` → `cloud/`.
- `-` `services/` — removed the now-empty directory.

### Give Device ownership of its dataset

**Context:** The supplied CSV was still at the repository root.

**User prompt**

> Since the data is related to the device, it should be contained within.

**Outcome:** Moved the dataset into the Device directory without changing its contents.

**Files modified**

- `→` `weather_data.csv` → `device/weather_data.csv`.
- `~` `PLAN.md` — updated the repository layout and dataset reference.

### Put the dataset under a data directory

**Context:** The preceding move had placed the CSV directly inside `device/`.

**User prompt**

> Should be under data/.

**Outcome:** Separated source data from application code/configuration.

**Files modified**

- `→` `device/weather_data.csv` → `device/data/weather_data.csv`.
- `~` `PLAN.md` — updated the final dataset path. Git records the unchanged-file relocation in `1f1f04f`.

### Replace custom Device encryption with HTTPS

**Context:** The plan still used application-level ChaCha20 on the Device → Gateway link.

**User prompt**

> Are we sure we want to use ChaCha? Would HTTPS be more secure?
> Okay, let's do it. Since it's simpler, we should strive for simplicity where possible.

**Outcome:** Recommended standard TLS over a custom ChaCha20 protocol, which would have required its own authentication, nonce management, replay protection, and key rotation. Simplified the Device hop to HTTPS with a pinned Gateway certificate and a provisioned device token; ML-KEM-derived encryption remained on Gateway → Cloud. Application-level encryption on the Device hop returned in Session 4, as AES-256-GCM.

**Files modified**

- `~` `PLAN.md` — removed device-side encryption/nonce handling and updated the related tests, metrics, and documentation requirements.

### Pin the implementation's Python version

**Context:** The crypto spike used Python 3.13, but the user wanted the actual implementation pinned to Python 3.14.7 rather than an automatically advancing version.

**User prompt**

> Don't update the pin; we should use 3.14.7 (the stable version at the start of the implementation).

**Outcome:** Fixed the planned runtime version at `3.14.7`; the spike image was not treated as the application-runtime decision.

**Files modified**

- `~` `PLAN.md` — pinned the service-image requirement to Python `3.14.7-slim`. The actual Python pin/manifests were created during scaffolding below.

### Require HTTPS for all network traffic

**User prompt**

> HTTP? Shouldn't it be HTTPS?

**Outcome:** Corrected a remaining generic HTTP reference; on the follow-up request to revise the plan, stated explicitly that all network traffic uses HTTPS and that Gateway → Cloud additionally encrypts payloads with an ML-KEM-derived key.

**Files modified**

- `~` `PLAN.md` — replaced ambiguous HTTP wording with HTTPS throughout.

### Start the AI usage record

**User prompt**

> It is important to document AI prompts and results.

**Outcome:** Established a record of significant user prompts, outcomes, decisions, changes, and verification rather than complete transcripts.

**Files modified**

- `+` `docs/AI_USAGE.md` — initial architecture/spike entries.
- `~` `PLAN.md` — added the record's location and ongoing documentation requirement.

### Guide user-performed uv scaffolding

**Context:** The user wanted to create the workspace manually rather than have the assistant perform all initialization.

**User prompt**

> Help me scaffold the project. Give me native uv commands where possible; I'll do this by hand with your help.

**Outcome:** Provided native uv initialization/install commands, tested the proposed layout in a temporary directory, and inspected the user's generated workspace. The retained scaffold had per-service manifests, package skeletons, one lockfile, and a root Python pin—not implemented services.

**Files created through the guided work**

- `+` `pyproject.toml` — root project, uv workspace members, and shared development group.
- `+` `device/pyproject.toml`, `gateway/pyproject.toml`, `cloud/pyproject.toml` — service metadata and initial package/build configuration.
- `+` `device/src/device/__init__.py`, `gateway/src/gateway/__init__.py`, `cloud/src/cloud/__init__.py` — initial service skeletons.
- `+` `.python-version`, `uv.lock` — Python `3.14.7` pin and shared resolution.

**Verification:** Inspected manifests, workspace members, Python selection, lock consistency, and skeleton commands. The scaffold and earlier hook/dataset work are tracked in `1f1f04f`.

### Reconsider and keep per-service packages

**Context:** The user questioned the nested `device/src/device/` layout. The assistant said packaging was not strictly required and that non-package applications would be simpler.

**User prompts**

> Right, then delete the src folder and .toml from those directories.

> Would having it as packages make it simpler to do integration tests?

**Outcome:** Removed the per-service `src/` directories, service manifests, and workspace configuration, then explained that integration tests should exercise services as black boxes over HTTPS/Compose rather than import their internals. The user then regenerated the per-service package workspace by hand; the assistant verified the `3.14.7` pin, workspace members, matching package directories/entry points, a valid `uv.lock`, and the generated commands.

**Files modified**

- `-`/`+` `device/`, `gateway/`, `cloud/` `src/` packages and `pyproject.toml` files — removed by the assistant, then recreated by the user; the retained result is the package workspace in `1f1f04f`.
- `~` `PLAN.md` — updated for the flat layout, then for the restored uv workspace.

### Use prek to run the hooks

**User prompt**

> Use prek instead of pre-commit? https://github.com/j178/prek

**Outcome:** Confirmed compatibility with the existing YAML and provided installation/hook commands. Chose prek as the runner while retaining Pyright and remote hook repositories.

**Files modified**

- `~` `PLAN.md` — changed the planned hook runner from pre-commit to prek.

The retained scaffold's root development dependency/lockfile includes prek. The installation commands were guidance to the user, not an assistant-performed application change.

### Restore portable YAML hook configuration

**Context:** The user had converted the hook configuration to `prek.toml`; retaining YAML would support both prek and pre-commit.

**User prompt**

> I already migrated, but bring back the YAML file.

**Outcome:** Removed the competing TOML configuration so `.pre-commit-config.yaml` was active again.

**Files modified**

- `-` `prek.toml` — temporary, untracked alternative configuration.
- `.pre-commit-config.yaml` — retained as the active configuration; no rewrite was needed at this step.

**Verification:** `prek validate-config` passed.

### Drop the dedicated import-sorting hook

**Context:** After the Ruff rule-set discussion, the user wanted to know whether the separate sort-imports hook was still needed.

**User prompt**

> Let's try removing the explicit line to sort imports in prek pre-commit.

**Outcome:** Confirmed with an intentionally unsorted file that the single `ruff-lint` hook detected and fixed import order without the dedicated hook. Also showed that `extend-ignore = ["I"]` disables sorting, so it was not adopted.

**Files modified**

- `~` `.pre-commit-config.yaml` — removed the dedicated sort-imports hook. The committed configuration (`1f1f04f`) runs only `uv-lock`, `ruff-lint`, and Pyright. The `ruff-format` hook was also gone by then, but the session does not show an assistant edit removing it.

**Verification:** Hook runs failed and auto-fixed on the unsorted probe, then passed. Probe files and the temporary ignore setting were removed before this session ended.

## Session 2 — Initial implementation specification

### Expand the agreed plan into a specification

**Context:** `PLAN.md` described the initial architecture, but implementation contracts and acceptance criteria still needed to be made concrete.

**User prompt**

> @PLAN.md Write a specification.

**Outcome:** Produced a local specification with requirements, APIs/data contracts, configuration, crypto framing, and acceptance criteria. This was an intermediate design with an HTTPS-only Device hop, superseded by Session 4.

**Files modified**

- `+` `SPEC.md` — temporary, untracked specification; never entered the final tree or Git history.
- `~` `docs/AI_USAGE.md` — recorded the specification work.

**Verification:** Compared the draft with the plan. No application or runtime tests were performed. `CONTEXT.md` and `PLAN.md` also remained untracked drafts.

## Session 3 — Payload cipher and migration goal

### Prefer AES-GCM for ML-KEM-derived payload protection

**Context:** The draft used ChaCha20-Poly1305 after ML-KEM/HKDF. The discussion clarified that ML-KEM establishes a secret but does not itself encrypt observation payloads.

**User prompt**

> Prefer AES.

**Outcome:** Selected ML-KEM-768 → HKDF-SHA-256 → AES-256-GCM. HTTPS remained the transport layer; AES-GCM supplied payload protection from the ML-KEM-derived key.

**Files modified**

- `~` `PLAN.md` — replaced the proposed payload cipher.
- `~` `SPEC.md` — changed cipher references in user stories, envelope framing, and the crypto-library profile.

**Verification:** Inspected the substitutions; no runtime tests. These drafts were superseded by Session 4; `08515e8` contains the final bridge requirements, not the draft files.

### State the migration goal

**Context:** The user had asked whether HTTP plus application-level AES could replace HTTPS on the Device hop, and where AES belonged.

**User prompt**

> What do you recommend, then? The goal of the project is to simulate the post-quantum migration. The idea is that we have devices that aren't powerful enough to handle ML-KEM, so we have a gateway between the legacy device and the cloud. Previously, we can assume legacy device → cloud, but now we need legacy device → gateway → cloud.

**Outcome:** Framed the migration as: before, Device → Cloud over ordinary TLS; after, the Device keeps its existing TLS capability toward the Gateway, while only Gateway and Cloud adopt post-quantum protection: hybrid post-quantum TLS where supported, otherwise HTTPS plus ML-KEM → HKDF → AES-256-GCM payload encryption. Recommended keeping AES out of the Device application. Session 4 revised the Device hop to explicit AES-256-GCM.

**Files modified:** None; `SPEC.md` already matched the recommendation and was left unchanged.

## Session 4 — Goal correction, PRD, and FRD

### Start an implementation-ready requirements discussion

**Context:** The project goal existed, but the meaning of ML-KEM and the Gateway's role still needed clarification before final requirements could be written.

**User prompt**

> @GOAL.md This is the task. Convert the idea into a PRD and FRD to be developed. Have a discussion to fill in the technical and knowledge gaps.

**Outcome:** Reviewed the goal, workspace, dependencies, and weather dataset, then opened a discussion of security scope, credentials, delivery, simulation limits, and verification. The PRD/FRD were finalized after the answers below, not immediately after this request.

**Files modified:** None yet; requirements elicitation and research only.

### Clarify what the Gateway modernizes

**User prompt**

> Correct the ML-KEM first. It's not what I thought it was. Help me understand what I am looking for. What would have happened previously, and what is the gateway solving?

**Outcome:** Explained classical key establishment versus ML-KEM, symmetric payload encryption, and the Gateway's decrypt/validate/reencrypt boundary. Established that the Gateway sees plaintext and that the project does not provide Device-to-Cloud end-to-end post-quantum protection.

**Files modified:** None; this clarification led to the goal edit below.

### Correct the goal without expanding its scope

**Context:** The preceding explanation exposed wording that treated ML-KEM as payload encryption and did not make the trusted plaintext boundary explicit.

**User prompt**

> Fix GOAL.md without changing much.

**Outcome:** Kept the original project scope while correcting the cryptographic data flow and security claim.

**Files modified**

- `~` `GOAL.md` — changed “post-quantum encryption” to key establishment; specified Device AES-256-GCM, Gateway decryption/validation, Cloud ML-KEM decapsulation plus AES-GCM decryption, and the trusted Gateway/no-end-to-end-PQ limitation.

### Simplify credential provisioning and PoC scope

**Context:** The assistant asked how the Gateway should trust the Cloud public key and proposed production-shaped options including mTLS. This is the user's free-text answer to that question.

**User answer**

> Keep it simple but secure. What makes the most sense? Perhaps my previous response was false; this is a PoC, but it should be done well.

**Outcome:** Reset the design toward a well-built educational PoC: pinned ML-KEM public keys, a bearer token over verified HTTPS, and manual rotation rather than production PKI, durable queues, or KMS infrastructure. The subsequent choices kept one simulated Device.

**Files modified:** None at this point; incorporated into the final PRD/FRD below.

### Define evidence for the Device's limitations

**Context:** The assistant asked whether to document constraints, enforce Docker resource limits, or benchmark cryptographic costs. This is the user's free-text answer.

**User answer**

> Docker limits, as well as benchmarks/tests to prove the restrictions.

**Outcome:** Required resource limits and repeatable benchmarks/tests. A later scope choice explicitly treated these as supporting evidence, not faithful ESP8266 emulation or proof of algorithm infeasibility. Benchmark timing would be informational, not a host-dependent CI threshold.

**Files modified:** None yet; the requirement was captured in PRD/FRD, then implemented in Session 9.

### Defer an analytics/read interface

**Context:** The assistant asked whether stored observations should be exposed through SQL/tests, a read-only API, or console summaries. This is the user's free-text answer.

**User answer**

> Out of scope for now. We will create some analytic view, perhaps.

**Outcome:** Deferred analytics/read APIs. The first release would persist observations and verify storage through tests rather than build an extra product interface.

**Files modified:** None yet; recorded as a scope exclusion in PRD/FRD.

### Define replay identity and finalize the requirements

**Context:** The user had chosen continuous dataset replay. The assistant then asked whether later cycles should reuse identifiers, create new transmission IDs, or shift the simulated observation period. This is the user's free-text answer.

**User answer**

> Shift the year +1.

**Outcome:** Specified one-year calendar shifts per cycle, skipping leap days invalid in the target year. With this and the preceding answers, finalized the trusted AES-GCM/ML-KEM bridge, at-least-once delivery with idempotent PostgreSQL insertion, JSON/base64 envelopes, generated gitignored secrets, manual current/previous KEM-key rotation, and extended failure tests. Preferred the standardized `cryptography` API over `liboqs-python`; deferred multiple devices, durable queues, automated rotation, PKI/KMS infrastructure, and analytics/read APIs.

**Files modified**

- `+` [`docs/PRD.md`](PRD.md) — product scope, requirements, success criteria, risks, and exclusions.
- `+` [`docs/FRD.md`](FRD.md) — protocol/crypto contracts, observation identity and calendar transformations, APIs/SQL, retry rules, provisioning/rotation, deployment, and verification traceability.
- `~` `docs/AI_USAGE.md` — replaced the earlier record with this requirements discussion and its decisions.

**Verification:** Reviewed the 366-row leap-year dataset; checked [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf), the [`cryptography` ML-KEM API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mlkem/), [OpenSSL support](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/), and [ESP8266 constraints](https://documentation.espressif.com/0a-esp8266ex_datasheet_en.pdf). Checked Markdown and PRD-to-FRD traceability; no application tests. The goal and requirements first entered Git in `08515e8`.

### Condense the AI record

**Context:** The newly generated requirements log included more discussion detail than was useful for the significant-work record.

**User prompt**

> Clean up AI_USAGE.md to capture the most relevant information.

**Outcome:** Condensed the record while retaining the significant prompt, relevant results, accepted/modified/rejected decisions, and verification evidence.

**Files modified**

- `~` `docs/AI_USAGE.md` — reduced the then-current record from 70 to 47 lines; no requirements or application code changed.

## Session 5 — PRD and FRD review corrections

**Model:** `gpt-6-astra`.

### Review and correct the requirements before implementation

**User prompts**

> Review the @docs/PRD.md and @docs/FRD.md.

> Fix it.

**Outcome:** The review identified retry loops for permanent upstream/certificate failures, missing behavior for unusable datasets, overly broad secret mounts, uncoordinated deadlines, ambiguous timezone metadata, unsafe exception logging, and an underspecified bootstrap path. “Fix it” approved correcting all of them; the requirements and matching verification cases were updated before service implementation began.

**Files modified**

- `~` `docs/PRD.md` — required fatal handling of permanent upstream/TLS failures, a Device deadline exceeding forwarding time, failure on zero valid observations, source timezone preservation, minimal secret mounts, sanitized logs, and containerized bootstrap.
- `~` `docs/FRD.md` — defined fatal `502 upstream_rejected` versus retryable failures; bounded forwarding attempts/total deadlines and the Device margin; enumerated service-specific secret mounts; kept CA signing/staged keys out of runtime mounts; expanded TLS, dataset, deadline, isolation, and bootstrap checks.
- `~` `docs/AI_USAGE.md` — recorded the review and fixes.

**Verification:** Requirements consistency and whitespace checks passed; runtime verification remained pending. Corrected documents first entered Git in `08515e8`.

## Session 6 — Legacy Device implementation and modularization

### Implement the legacy sender

**Context:** The reviewed requirements called for a single constrained-device simulator, AES-GCM envelopes, verified TLS 1.2, and continuous calendar-shifted weather replay.

**User prompt**

> @docs/FRD.md @docs/PRD.md @GOAL.md Implement the legacy device.

**Outcome:** Implemented validated environment settings, two-section CSV parsing, calendar-year cycling, AES-256-GCM envelopes, TLS-1.2-only delivery, bounded retry/permanent-failure handling, and safe lifecycle logging. Retried in memory with regenerated envelopes; added no checkpoint, queue, server, or shared framework.

**Files modified**

- `~` `device/src/device/__init__.py` — initial Device CLI and application logic; moved into modules by the next prompt.
- `~` `device/pyproject.toml` — runtime dependencies for cryptography, HTTPX, Pydantic/settings, and timezone support.
- `+` `device/Dockerfile` — standalone Python `3.14.7` service image with locked dependency installation.
- `+` `device/tests/test_device.py` — parser/calendar, crypto, validation, and delivery/retry tests.
- `~` `pyproject.toml`, `uv.lock` — pytest/Pyright configuration and workspace dependency resolution.
- `~` `docs/AI_USAGE.md` — implementation record.

**Verification:** Seven tests passed; Ruff and Pyright passed. Parsed 366 source observations and produced 365 in the next-year cycle after skipping its invalid leap day. Built the image, confirmed Python `3.14.7`, and checked safe failure when required settings were absent.

### Move logic out of the package initializer

**Context:** The initial implementation put orchestration and application logic in `__init__.py` rather than focused modules.

**User prompt**

> We should not code application logic inside of `__init__.py`. Create a file `main.py`; create modular, maintainable code where possible.

**Outcome:** Split the application into maintainable modules and made the initializer a docstring-only package marker. The console command targeted `device.main:main` at this stage; Session 10 records the later installable layout.

**Files modified**

- `~` `device/src/device/__init__.py` — removed application logic.
- `+` `device/src/device/main.py` — process entry point and orchestration.
- `+` `device/src/device/config.py`, `device/src/device/models.py` — validated settings and observation/envelope contracts.
- `+` `device/src/device/dataset.py` — CSV parsing and calendar transformation.
- `+` `device/src/device/crypto.py`, `device/src/device/delivery.py`, `device/src/device/errors.py` — encryption, HTTP/retry behavior, and safe errors.
- `~` `device/pyproject.toml`, `device/tests/test_device.py`, `uv.lock` — entry point, imports, and package resolution.
- `~` `docs/AI_USAGE.md` — modularization record.

**Verification:** Prek hooks and all seven tests passed. Rebuilt the image and checked the console command and `python -m device.main`. The Device implementation/modular code is tracked in `08515e8`; paths above describe the recorded stage.

## Session 7 — Gateway implementation and Device integration

### Implement the cryptographic bridge

**Context:** Device existed; Cloud would be implemented separately. Integration therefore needed to prove Device wire compatibility and the forwarded Cloud envelope without pretending the Cloud service already existed.

**User prompt**

> @GOAL.md @docs/PRD.md @docs/FRD.md The legacy device should now be implemented. Implement the gateway and make sure its integration works with the legacy device.

**Outcome:** Implemented bounded HTTPS parsing, strict Device-envelope validation, AES-GCM decryption/observation validation, fresh ML-KEM-768 encapsulation plus HKDF/AES-GCM forwarding, bearer authentication, bounded retries/deadlines, health reporting, and sanitized logs. Kept independent protocol models and used injected HTTPX transports for deterministic integration coverage rather than a shared framework.

**Files modified**

- `+` `gateway/src/gateway/app.py` — observation endpoint, bounded validation, health reporting, and error mapping.
- `+` `gateway/src/gateway/crypto.py` — Device AES-GCM decryption and Cloud ML-KEM/HKDF/AES-GCM envelopes.
- `+` `gateway/src/gateway/forwarding.py` — authenticated Cloud delivery, retry classification, and total forwarding deadline.
- `+` `gateway/src/gateway/config.py`, `gateway/src/gateway/models.py`, `gateway/src/gateway/errors.py` — validated material/settings, independent wire models, and safe errors.
- `+` `gateway/src/gateway/main.py`, `gateway/src/gateway/__init__.py`; `~` `gateway/src/main.py` — TLS process entry and compatibility launcher.
- `+` `gateway/tests/test_gateway.py` — invoked real Device delivery against Gateway ASGI; decrypted the forwarded envelope; verified fresh encapsulation after transient failure, ciphertext tampering, and permanent Cloud rejection.
- `+` `gateway/Dockerfile`; `~` `gateway/pyproject.toml` — standalone service image and runtime dependencies.
- `~` `pyproject.toml`, `uv.lock`, `docs/AI_USAGE.md` — workspace test/type-check paths, resolution, and record.

**Verification:** Eleven tests, Ruff, and Pyright passed. Built the image, imported the app inside it, and ran an ML-KEM round trip. Startup validated the raw 1,184-byte pinned public key and local crypto/TLS material. Tracked in `6b6bbf5`.

## Session 8 — Cloud service implementation

### Authenticate, decrypt, and persist observations

**Context:** Device and Gateway existed; Cloud needed to consume Gateway's ML-KEM-derived envelope and persist observations idempotently.

**User prompt**

> @GOAL.md @docs/PRD.md @docs/FRD.md The legacy device and gateway should now have been implemented. Implement the cloud service.

**Outcome:** Implemented bearer authentication before parsing/crypto work, bounded strict envelopes, current/previous-key selection and decapsulation, HKDF/AES-GCM decryption, plaintext validation, and idempotent PostgreSQL storage. Used direct parameterized SQL and short-lived asyncpg connections at this stage; Session 9 introduced pooling. Errors stayed generic and logs excluded payloads/secrets.

**Files modified**

- `+` `cloud/src/cloud/app.py` — observation API, authentication ordering, validation, storage acknowledgement, and database-aware health.
- `+` `cloud/src/cloud/crypto.py` — validated key IDs, active PEM PKCS#8 key loading, ML-KEM decapsulation, and envelope decryption.
- `+` `cloud/src/cloud/database.py`, `cloud/schema.sql` — asyncpg transactions and uniqueness-based persistence.
- `+` `cloud/src/cloud/config.py`, `cloud/src/cloud/models.py`, `cloud/src/cloud/errors.py` — validated settings, independent protocol models, and safe database/service errors.
- `+` `cloud/src/cloud/main.py`, `cloud/src/cloud/__init__.py`; `~` `cloud/src/main.py` — TLS 1.3 startup and compatibility launcher.
- `+` `cloud/tests/test_cloud.py` — authentication, crypto/validation failures, idempotency, health, and Gateway-generated envelope compatibility.
- `+` `cloud/Dockerfile`; `~` `cloud/pyproject.toml` — service image and runtime dependencies.
- `~` `pyproject.toml`, `uv.lock`, `docs/FRD.md`, `docs/AI_USAGE.md` — workspace configuration/resolution, technology profile, and record.

**Verification:** Fourteen tests, Ruff, and Pyright passed after full workspace sync. A Cloud image build succeeded during implementation. Tracked in `a924d42`.

## Session 9 — Audit remediation and strict typing

**Model:** `gpt-6-astra`.

### Audit the existing implementation

**User prompt**

> Perform a thorough audit of the current implementation. Identify security issues, performance issues, dead code, and implementation issues. Report back any findings, ranking them by priority from 1–10.

**Outcome:** Ranked 13 findings. Missing deployment/bootstrap and unbounded database operations were 8/10; forged validation logs, stalled request bodies, and absent real integration coverage were 7/10. Remaining findings covered response buffering, connection churn, malformed bearer headers, secret exclusions, root containers, missing benchmarks, invalid key filenames, and redundant entry points/test support. The core library-based cryptographic flow appeared sound, but passing unit tests did not establish deployment security.

**Files modified:** None; reviewed service code, tests, SQL, Dockerfiles, and requirements, and reported findings.

**Verification:** Existing 14 tests passed. Reproduced log injection, oversized-response buffering, malformed-bearer errors, and unusable Unicode key IDs. No real-stack execution or dependency-CVE scan was performed during this review.

### Remediate the audit findings

**Context:** “All the issues” refers to the 13 findings reported above.

**User prompt**

> Record this prompt and fix all the issues.

**Outcome:** Addressed all 13 findings with isolated deployment, bounded HTTP/database resources, sanitized logging/credentials, real-stack security tests, non-root runtime images, and repeatable benchmarks. Used asyncpg's built-in pool without a new runtime dependency. Retained/documented useful compatibility launchers and the AAD verification helper rather than indiscriminately deleting them.

**Files modified**

- `+` `docker-compose.yml` — separate internal Device/Cloud networks, dependency health ordering, PostgreSQL schema/persistent volume, minimal secret mounts, Device CPU/memory limits, read-only application filesystems, dropped capabilities, and no-new-privileges.
- `+` `tools/bootstrap.py`, `tools/Dockerfile` — self-contained provisioning of TLS/AES/bearer/ML-KEM/database material with private permissions and explicit overwrite refusal. CA signing and staged keys stay outside runtime mounts; `--force` is a destructive development reset, not migration.
- `~` `cloud/src/cloud/database.py`, `cloud/src/cloud/app.py` — four-connection pool, bounded acquisition/queries/locks/inserts/readiness/shutdown, pool lifecycle, bounded upload reads, and safe bearer handling.
- `~` `gateway/src/gateway/app.py`, `gateway/src/gateway/errors.py`, `device/src/errors.py` — five-second body-read deadline and bounded, allowlisted validation/error logging instead of attacker-controlled locations.
- `~` `gateway/src/gateway/forwarding.py`, `device/src/delivery.py` — streamed, size-bounded responses checked before buffering/parsing; rejected compression before decoding.
- `~` `cloud/src/cloud/crypto.py` — ASCII protocol-compatible private-key filenames.
- `~` `gateway/src/gateway/main.py`, `cloud/src/cloud/main.py` — server concurrency/backlog/shutdown bounds and removal of redundant module-level application instances.
- `~` `gateway/src/gateway/crypto.py` — removed an unreachable JSON-decode handling branch; retained the useful AAD helper.
- `~` `device/Dockerfile`, `gateway/Dockerfile`, `cloud/Dockerfile` — unprivileged runtime users.
- `+` `.gitignore`, `.dockerignore` — excluded generated credentials and build/test artifacts from Git and image contexts.
- `+` `tests/test_security.py`, `tests/test_tls.py`, `tests/integration/test_stack.py`; `~` `cloud/tests/test_cloud.py` — regression checks, real loopback TLS rejection, real PostgreSQL/stack behavior, and authenticated-metadata tampering.
- `+` `tools/check_deployment.py`, `tools/integration.sh` — rendered-Compose security/deadline checks and repeatable TLS/PostgreSQL integration execution.
- `+` `tools/benchmark.py`, `tools/benchmark.sh`, `docs/BENCHMARK.md` — primitive/envelope timing, RSS/image-size measurements, and a checked-in sample report.
- `~` `README.md`, `docs/AI_USAGE.md` — startup, provisioning, recovery, credential-reset warnings, compatibility/support rationale, and verified remediation results.

**Verification:** Ruff, Pyright, whitespace checks, and **42 tests passed, 5 skipped**. Built runtime and Tools images. Integration passed twice after deployment fixes: five real-stack checks, six real TLS rejection checks, rotation overlap/new/retired keys, 731 rows across two cycles, replay without growth, independent restarts, Cloud outage recovery, database lock/pool exhaustion recovery, no direct Device-to-Cloud route, and sanitized logs. Benchmarks completed 1,000 measured operations after 20 warm-ups. Fixed rendered-Compose string-valued memory normalization before final checks.

**Limits:** Educational PoC, not security certification. Benchmarks exclude network/database latency and ESP8266 timing. No dependency-CVE scan or sustained adversarial load test. Containers were stopped without deleting local credentials or retained database data. Remediation and the following typing work are tracked together in `db9f063`.

### Fix strict typing without suppressions

**Context:** The user enabled strict Pyright after remediation, exposing missing and opaque types across services, tools, and tests.

**User prompt**

> I just introduced strict Pyright mode. This causes things to fail. Make sure all files pass in strict mode. Don't use ignore comments; fix the actual issues, no band-aids.

**Outcome:** Preserved strict/all-file coverage and corrected contracts rather than relaxing diagnostics. Removed type-ignore comments and untyped response access, used concrete paths/key types and typed lifecycle generators, and replaced tests' private/unvalidated shortcuts with public interfaces and valid settings.

**Files modified**

- `~` `pyproject.toml`, `uv.lock` — added development-only `asyncpg-stubs`.
- `~` `device/src/config.py`, `gateway/src/gateway/config.py`, `cloud/src/cloud/config.py` — explicit `from_environment()` validation factories; no fabricated required defaults, unchecked constructors, or casts.
- `~` `gateway/src/gateway/app.py`, `cloud/src/cloud/app.py` — concrete key/path contracts and `AsyncGenerator` lifespans.
- `~` `device/src/delivery.py` — exhaustive structural matching of untrusted response objects instead of `Any`/untyped dictionary access.
- `~` `device/src/main.py`, `gateway/src/gateway/main.py`, `cloud/src/cloud/main.py`, `tools/bootstrap.py`, `tools/benchmark.py` — typed settings construction, callbacks, paths/key objects, and benchmark collections.
- `~` `tests/test_security.py`, `tests/test_tls.py`, `tests/integration/test_stack.py` — annotated fixtures, real forwarding dependencies, public HTTP/pool lifecycle tests, and black-box database concurrency checks.
- `+` `tests/test_settings.py` — validation of required fields, identifiers, file existence, and defaults.
- `~` `docs/AI_USAGE.md` — strict-typing work and verification.

**Verification:** Strict Pyright reported zero diagnostics; Ruff, formatting, and whitespace checks passed; **45 tests passed, 5 skipped**. Real-stack integration passed, including six TLS rejection checks and 731-row replay/restart/outage/rotation/isolation checks. Refreshed PostgreSQL's transaction-cached activity snapshot in the concurrency test before each observation. The source scan at this stage found no type-ignore comments, `Any` annotations, casts, or `model_construct` calls. Tracked with remediation in `db9f063`.

## Session 10 — CI workspace coverage and service packaging

### Cover every workspace service in CI

**Context:** The initial workflow did not correctly install/test the whole workspace or build the independently deployed service artifacts.

**User prompt**

> I just introduced CI into this repository. Make it work for all the packages/services in this project. Upgrade versions where possible. Install the dependencies, if needed, as dev dependencies.

**Outcome:** Installed the locked workspace for lint/format/strict typing/unit tests/deployment checks; replaced an invalid root build with four image jobs. Added least-privilege permissions, push/PR triggers, caching, concurrency cancellation, timeouts, and non-fail-fast builds.

**Files modified**

- `~` `.github/actions/setup/action.yaml` — changed Setup Python v5 → v7, setup-uv `@v6` → `@v10`, and uv `0.8.0` → `0.12.17`; retained the repository Python pin and configured lockfile caching.
- `~` `.github/workflows/code-quality.yaml` — replaced isolated dependency/quality jobs and the root `uv build` with a locked-workspace quality job and four-image matrix; changed Checkout v4 → v7 and added broader triggers, permissions, concurrency, and timeouts.
- `~` `pyproject.toml`, `uv.lock` — added Ruff/Pyright as development dependencies and the root pytest import path.
- `~` `device/Dockerfile`, `gateway/Dockerfile`, `cloud/Dockerfile`, `tools/Dockerfile` — uv image pin `0.12.15` → `0.12.17`.
- `~` `README.md`, `docs/AI_USAGE.md` — development/CI commands and verified coverage.

**Verification:** Locked sync, Ruff, strict Pyright, hooks, rendered deployment checks, and **45 tests passed, 5 skipped**. All four images built; no outdated direct dependencies were reported. Tracked in `96d343c`. These local checks did not prove GitHub could resolve the setup-uv major tag; Session 13 records that correction.

### Adopt installable service packages

**Context:** Gateway and Cloud used `src/<service>/` package layouts but were marked `package = false` and ran from source through `PYTHONPATH`; the Device modules sat directly under `device/src/`.

**User prompts**

> Cloud and Gateway have an additional nested directory because they were initially created as packages (`uv init --package`). Is package the correct approach here? Would it make more sense to have src/ without the additional nesting layer of src/gateway and src/cloud?

> The device is meant to be a simulation of an Arduino device. This is a monorepo, but they're supposed to work in isolation. The gateway is supposed to live alongside the legacy device, probably in the same network and facility. The cloud is meant to simulate a service like using avs or something similar. We want to be able to deploy these individually but still develop them in a monorepo. What would you recommend: should package be false or not?

> Update the code.

**Outcome:** Explained that `src/` is the import root and `<service>/` the namespace, so flattening would create colliding top-level modules (`app`, `config`, `main`) across services. Distinguished Python installation/import packaging from runtime deployment and recommended independently installable service packages, a virtual root workspace, separate Docker images/runtime dependencies, and wire-level compatibility tests rather than cross-service imports or a shared framework. “Update the code” approved the proposal: standardized installable `src/<service>/` packages and console commands while preserving independent deployments and one shared lockfile, and removed reliance on source-tree `PYTHONPATH`.

**Files modified**

- `→` `device/src/{config,crypto,dataset,delivery,errors,main,models}.py` → corresponding files under `device/src/device/`; `+` `device/src/device/__init__.py` — namespaced Device imports and a package marker.
- `-` `gateway/src/main.py`, `cloud/src/main.py` — removed redundant top-level compatibility launchers.
- `~` `device/pyproject.toml`, `gateway/pyproject.toml`, `cloud/pyproject.toml` — replaced non-package configuration with `uv_build` backends and `mlkem-device`, `mlkem-gateway`, `mlkem-cloud` console commands.
- `~` `pyproject.toml`, `uv.lock` — virtual root `package = false`, installed-service test imports, and editable package resolution.
- `~` `device/Dockerfile`, `gateway/Dockerfile`, `cloud/Dockerfile`, `tools/Dockerfile` — locked non-editable package installation and installed entry points instead of `PYTHONPATH`.
- `~` `device/tests/test_device.py`, `gateway/tests/test_gateway.py`, `tests/test_settings.py`, `tests/test_security.py`, `tests/test_tls.py`, `tests/integration/test_stack.py` — updated namespaced imports.
- `~` `README.md` — revised service launch and development commands.

**Verification:** Ruff, strict Pyright, hooks, whitespace checks, and **45 tests passed, 5 skipped**. Built wheels/source distributions and all four images; container imports resolved from `.venv/site-packages`, not source directories. Tracked in `6a386ec` after the independent verification in Session 11.

## Session 11 — Independent verification of service packaging

### Check the package migration before committing

**Context:** A new conversation received the Session 10 change summary and requested independent verification. The quote is an edited excerpt of the instruction at the end of that pasted summary.

**User prompt — excerpt**

> Verify the changes before committing.

**Outcome:** Found no blocking issues in the packaging migration. Verification did not introduce additional application changes; the verified package change is `6a386ec`.

**Files modified:** None; inspected the service/root manifests, lockfile, Dockerfiles, README commands, imports, and test changes from Session 10.

**Verification:** Ruff, strict Pyright, hooks, whitespace checks, and **45 tests passed, 5 skipped**. Built all three wheels/source distributions, installed wheels in a clean virtual environment, verified console commands/imports, built all four images, and confirmed installed-package imports inside containers.

## Session 12 — Live observability and JSONL logging

### Choose a way to demonstrate the live pipeline

**User prompt**

> Observability is important in this project to demonstrate things were implemented properly. Are there services I can use to demonstrate what was accomplished, how the data is travelling, etc.?

**Outcome:** Recommended OpenTelemetry instrumentation with Grafana's LGTM stack (Loki logs, Tempo traces, Prometheus metrics, Grafana dashboards) as an optional Compose overlay, with only Grafana published on loopback. Follow-up questions established that Grafana provides a live dashboard, that Loki is a separate Grafana Labs service bundled in the demo image, and that the existing standard-library logging should be kept rather than adding Loguru.

**Files modified:** None; recommendation only.

### Implement JSONL logging and the observability stack

**User prompt**

> If possible, JSONL would be better and more readable coming from the local Python logging. Add other elements to support your recommended stack with Grafana, OpenTelemetry, etc.

**Outcome:** Added allowlisted standard-library JSONL logging with trace/span correlation, bounded telemetry, automatic FastAPI/HTTPX/asyncpg/logging instrumentation, explicit crypto/delivery/storage spans, and an opt-in segmented collector/LGTM deployment. Did not serialize arbitrary log attributes, request bodies, ciphertext, credentials, or key material into structured fields.

**Files modified**

- `+` `device/src/device/logging_config.py`, `gateway/src/gateway/logging_config.py`, `cloud/src/cloud/logging_config.py` — per-service JSONL formatters and safe field selection.
- `~` `device/src/device/main.py`, `device/src/device/dataset.py`, `device/src/device/delivery.py` — logging setup, structured lifecycle/dataset events, and delivery/encryption spans.
- `~` `gateway/src/gateway/main.py`, `gateway/src/gateway/app.py`, `gateway/src/gateway/forwarding.py`, `cloud/src/cloud/main.py`, `cloud/src/cloud/app.py` — correlated request, crypto, forwarding, and storage events/spans.
- `+` `docker-compose.observability.yml` — two segment-local collectors, LGTM, instrumentation environment, read-only/unprivileged collectors, and loopback-only Grafana exposure.
- `+` `observability/otel-collector.yaml`, `observability/dashboards-provisioning.yaml`, `observability/mlkem-overview.json` — telemetry pipelines, dashboard provisioning, and the live pipeline dashboard.
- `+` `tests/test_observability.py`, `tools/check_observability.py`; `~` `.github/workflows/code-quality.yaml` — injection-resistant JSONL tests and rendered segmentation/secret-mount/port checks in CI.
- `~` `device/pyproject.toml`, `gateway/pyproject.toml`, `cloud/pyproject.toml`, `uv.lock` — telemetry dependencies and resolution.
- `~` `README.md` — log/dashboard/startup instructions.

**Verification:** Ruff, Pyright, and **48 tests passed, 5 skipped**; base deployment and observability network checks passed; dashboard JSON validated; JSONL trace correlation verified. Containers could not be run at this point because the session lacked Docker access.

### Run the stack and verify access

**User prompt**

> Run the application and tell me how to access it.

**Outcome:** After the user granted Docker group access, built/started PostgreSQL, Cloud, Gateway, Device, both collectors, and LGTM. Verified the provisioned **ML-KEM Live Pipeline** dashboard at `http://127.0.0.1:3000`, Loki log ingestion, Prometheus metrics, and a shared 20-span Device/Gateway/Cloud Tempo trace.

**Files modified**

- `~` `docker-compose.observability.yml` — LGTM also joins a separate dashboard network because a container attached only to internal networks could not publish Grafana reliably; only `127.0.0.1:3000` is published.

### Clarify which services are exposed

**User prompt**

> How do I run all images, and are they exposed locally?

**Outcome:** Gave the combined base/overlay Compose commands. Only Grafana is published, on loopback; Device, Gateway, Cloud, PostgreSQL, collectors, Loki, Tempo, and Prometheus remain internal, and separate collectors preserve the Device/Cloud network boundary.

**Files modified:** None; explanation only.

### Load host-user IDs through dotenv

**Context:** Compose runs the services as the invoking user's UID/GID so they can read host-owned `0600` generated secrets; the previous instructions required exporting these as shell variables.

**User prompt**

> Why do we need to expose IDs like so? Could we make use of dotenv?

**Outcome:** Used Compose's automatic `.env` loading for `LOCAL_UID`/`LOCAL_GID` instead of exported shell variables. Follow-up questions confirmed the IDs are applied at container runtime (not baked into images, which default to `10001:10001`) and that the mapping is required by the secret-permission design.

**Files modified**

- `+` `.env` — untracked, gitignored, machine-specific UID/GID values; not application credentials.
- `~` `README.md` — replaced the shell-export instruction with a `printf … > .env` command and explained automatic Compose loading.

### Slow the Device to a five-minute send interval

**Context:** The Device sent one observation per second by default.

**User prompt**

> The data should be sent every 5 minutes.

**Outcome:** Changed the default interval to 300 seconds; the Device sends once at startup and then waits five minutes after each accepted observation. Tests and one-shot runs still override the interval with `SEND_INTERVAL_SECONDS=0`.

**Files modified**

- `~` `docker-compose.yml` — `SEND_INTERVAL_SECONDS` default `1` → `300`.
- `~` `README.md` — documented the five-minute default and `.env` override.
- `~` `.env` — local override for the running environment (untracked).

**Verification:** Recreated the Device container and confirmed the 300-second interval. The observability work and this interval change are tracked together in `27f53b4`.

## Session 13 — Resolve the setup-uv action release

### Fix the action-resolution failure

**Context:** CI failed while downloading actions because the selected setup-uv major tag did not resolve.

**User prompt**

> Prepare all required actions
> Getting action download info
> Error: Unable to resolve action `astral-sh/setup-uv@v10`, unable to find version `v10` — fix this issue and push.

**Outcome:** Replaced the unavailable major alias with a verified release tag while retaining the uv binary pin and cache settings.

**Files modified**

- `~` `.github/actions/setup/action.yaml` — `astral-sh/setup-uv@v10` → `astral-sh/setup-uv@v10.2.0`; uv remains `0.12.17`.

**Verification:** Confirmed `v10.2.0` with `git ls-remote`; whitespace checks passed. Hooks skipped Python/lockfile checks for the YAML-only change. An optional YAML-parser check could not run because PyYAML was absent; no successful hosted workflow run is recorded in this session. The one-line correction is tracked in `14e22f6`.
