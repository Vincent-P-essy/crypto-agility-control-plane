# Benchmark protocol

## Reproducibility contract

The structured report records sample count, Python, OpenSSL, liboqs, native-library hash,
OS, architecture, CPU model, and logical CPU count. Compare two reports only after checking
these fields and host load/power policy.

## TLS

Both peers use TLS 1.3 only, an ephemeral ECDSA P-256 certificate, no session tickets, and
fresh `SSLObject` instances. The classical pair forces X25519. The hybrid pair requires
OpenSSL 3.5 and uses its hybrid-preferred default. Every sample's ServerHello is parsed:

- X25519 group: `0x001d`;
- X25519MLKEM768 group: `0x11ec`.

The reported wire counts cover records emitted through handshake completion. Latency does
not include TCP, DNS, application work, or certificate-chain verification. The separate
compatibility matrix crosses classical-only and hybrid-preferred policies in the same
OpenSSL environment.

## Application primitives

The pinned native library performs ML-KEM-768 key generation, encapsulation, and
decapsulation plus ML-DSA-65 key generation, signing, and verification. The run is retained
only when secrets match, a valid signature verifies, and a modified message is rejected.

Sizes come from the loaded liboqs structures and actual signature output. The application
envelope-components size is ciphertext + signature + 32-byte benchmark message; framing,
base64 expansion, JSON, and TLS records are intentionally excluded.

## Statistics

One unreported warm-up precedes each operation. Wall and process CPU times use nanosecond
clocks and are converted to milliseconds. p50 and p95 use nearest rank. Throughput is
operation count divided by elapsed wall time for that measured loop. RSS is sampled at
process baseline and via the OS high-water counter; it is not attributed to one operation.
