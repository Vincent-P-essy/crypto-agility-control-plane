# Checked-in evidence

`evidence/benchmark-local.json` and its Markdown rendering are a real 200-sample run, not a
template. The environment was CPython 3.12.13, OpenSSL 3.5.7, liboqs 0.16.0, Linux x86-64,
and an Intel i3-1115G4. Re-run before comparing another machine.

Observed highlights from that report:

| Profile or operation | p50 | p95 | Additional evidence |
|---|---:|---:|---|
| TLS 1.3 / X25519 | 0.501 ms | 0.798 ms | group `0x001d`, 32-byte server key share |
| TLS 1.3 / X25519MLKEM768 | 0.677 ms | 0.878 ms | group `0x11ec`, 1120-byte server key share |
| ML-KEM-768 encapsulation | 0.011 ms | 0.014 ms | 1184-byte public key, 1088-byte ciphertext |
| ML-DSA-65 signing | 0.108 ms | 0.240 ms | 1952-byte public key, 3309-byte signature |

The TLS benchmark is in-memory and excludes DNS/TCP. The native operation timings exclude
TLS framing. RSS is process-level. These scope boundaries are embedded in the JSON.

`evidence/inventory/` is the CBOM and Markdown report generated from the synthetic fixture
with a 12-year confidentiality horizon. It contains evidence hashes, never raw key/token
values.
