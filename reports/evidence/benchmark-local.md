# Reproducible cryptographic benchmark

Report: `benchmark-sha256-f3296ad4f1a1997437d2e8b0713ec9882f7ee1a1e5d1dfe4a77139483f85a70d`
Generated: `2026-07-13T17:37:08.853913+00:00`
OpenSSL: `OpenSSL 3.5.7 9 Jun 2026`
liboqs: `0.16.0`
CPU: `11th Gen Intel(R) Core(TM) i3-1115G4 @ 3.00GHz`

## TLS handshakes

| Profile | Negotiated group | Key share | Wire C→S | Wire S→C | p50 | p95 | Throughput |
|---|---|---:|---:|---:|---:|---:|---:|
| standard-tls-1.3 | X25519 (0x001d) | 32 B | 315 B | 715 B | 0.501 ms | 0.798 ms | 1737.2/s |
| true-hybrid-tls-1.3 | X25519MLKEM768 (0x11ec) | 1120 B | 1549 B | 1803 B | 0.677 ms | 0.878 ms | 1429.9/s |

## Real application-layer PQC operations

These measurements call liboqs directly. They describe an experimental application envelope, not TLS negotiation.

| Operation | p50 wall | p95 wall | p50 CPU | Throughput |
|---|---:|---:|---:|---:|
| ML-KEM-768 key generation | 0.014 ms | 0.015 ms | 0.013 ms | 70390.0/s |
| ML-KEM-768 encapsulation | 0.011 ms | 0.014 ms | 0.011 ms | 86811.3/s |
| ML-KEM-768 decapsulation | 0.013 ms | 0.013 ms | 0.012 ms | 76959.9/s |
| ML-DSA-65 key generation | 0.034 ms | 0.061 ms | 0.034 ms | 24898.8/s |
| ML-DSA-65 signing | 0.108 ms | 0.240 ms | 0.107 ms | 7695.6/s |
| ML-DSA-65 verification | 0.032 ms | 0.040 ms | 0.031 ms | 30351.5/s |

## Client/server compatibility matrix

| Client policy | Server policy | Success | Negotiated group | Scope |
|---|---|---|---|---|
| classic-only | classic-only | yes | X25519 | Measured only with this report's Python/OpenSSL build; this is not evidence of browser or third-party client compatibility. |
| classic-only | hybrid-preferred | yes | X25519 | Measured only with this report's Python/OpenSSL build; this is not evidence of browser or third-party client compatibility. |
| hybrid-preferred | classic-only | yes | X25519 | Measured only with this report's Python/OpenSSL build; this is not evidence of browser or third-party client compatibility. |
| hybrid-preferred | hybrid-preferred | yes | X25519MLKEM768 | Measured only with this report's Python/OpenSSL build; this is not evidence of browser or third-party client compatibility. |

## Boundaries

- **standard tls:** TLS 1.3 with X25519 forced on both MemoryBIO peers.
- **true hybrid tls:** A real TLS 1.3 ServerHello negotiated X25519MLKEM768 (0x11ec). The OpenSSL 3.5 default policy is used and each sample is wire-verified; it is not a browser claim.
- **application pqc:** Real ML-KEM-768 encapsulation and ML-DSA-65 signatures using liboqs 0.16.0. This experimental envelope is not TLS negotiation or an ML-DSA certificate.
- **memory:** RSS is process-level baseline/high-water telemetry, not per-operation allocation.
