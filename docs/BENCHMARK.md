# Informational benchmark sample

Command: `sh tools/benchmark.sh`, measured 2026-09-20. Reports are regenerated under
`.local/benchmarks/`; values are not acceptance thresholds.

Environment: AMD Ryzen 5 5600X (6 cores), Linux 7.2.6-arch2-1 x86_64, container glibc
2.36, Python 3.14.7, cryptography 50.0.1, OpenSSL 4.0.2. Each operation received 20
warm-up calls followed by 1,000 measured calls. p95 uses nearest-rank selection.
The benchmark tool is not CPU/memory constrained; the Device demo container is.

| Operation | Median µs | p95 µs |
| --- | ---: | ---: |
| AES-256-GCM encrypt | 0.980 | 3.970 |
| AES-256-GCM decrypt | 0.910 | 0.950 |
| ML-KEM-768 encapsulate | 18.870 | 19.070 |
| ML-KEM-768 decapsulate | 27.540 | 28.721 |
| Gateway envelope creation | 41.870 | 51.020 |
| Cloud envelope decryption/validation | 50.275 | 59.230 |

Peak benchmark process RSS: **44,630,016 bytes**. This includes imports, all crypto
operations, and timing collections; it is not a Device-only memory measurement.

Docker image sizes from `docker image inspect` (uncompressed cumulative size, not
registry transfer size or incremental disk usage):

| Image | Bytes |
| --- | ---: |
| Device | 337,395,619 |
| Gateway | 342,749,602 |
| Cloud | 373,537,004 |

**Limitations:** These container measurements neither reproduce ESP8266 instruction
timing nor prove that ML-KEM is infeasible on that hardware. Network, database, and
end-to-end latency are not included. Results depend on host scheduling and load.
The separate integration run successfully stored 731 observations with Device
limited to 0.25 CPU and 128 MiB, including a replay and recovery exercises.
