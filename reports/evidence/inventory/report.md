# Crypto Bill of Materials

Document: `urn:cbom:sha256:26f6c19b2816a265a21f88ef6186dbf2e6017ccfc2c0d8d1c32c0cf6c15726ba`
Generated: `2026-07-13T17:31:08.319819+00:00`
Schema: `1.0.0`

## Executive summary

- Findings: 22
- Critical/high: 3 / 8
- HNDL planning flags: 8
- Migration actions: 12

The HNDL flag is a configurable planning horizon, not a forecast of quantum-computer availability.
Evidence stores locations and hashes only; JWT payloads, key bytes, and configuration values are not copied.

## Findings

| Algorithm | Use | Asset | Bits | Exposure | Risk | HNDL | Evidence |
|---|---|---|---:|---|---:|---|---|
| AES-128 | declared cryptographic algorithm | configuration | — | internal | 22 (low) | no | application.env.example:line:2 |
| TLS-1.2 | transport protocol | protocol | — | internal | 42 (medium) | no | service.yaml:line:3 |
| X25519MLKEM768 | declared cryptographic algorithm | configuration | — | internal | 15 (low) | no | service.yaml:line:9 |
| DES | declared cryptographic algorithm | configuration | — | internal | 100 (critical) | no | nginx.conf:line:4 |
| ED25519 | ssh algorithm configuration | configuration | — | internal | 62 (high) | yes | sshd_config:line:2 |
| ECDH | tls key agreement | configuration | — | internal | 65 (high) | yes | service.yaml:line:4 |
| X25519 | ssh algorithm configuration | configuration | — | internal | 62 (high) | yes | sshd_config:line:3 |
| LIBRARY-CRYPTOGRAPHY | cryptographic library dependency | library | — | internal | 12 (low) | no | requirements.txt:line:1 |
| TLS-1.0 | transport protocol | protocol | — | internal | 100 (critical) | no | nginx.conf:line:3 |
| HS256 | jwt signature | configuration | — | internal | 35 (medium) | no | application.env.example:line:1 |
| ML-DSA-65 | declared cryptographic algorithm | configuration | — | internal | 13 (low) | no | service.yaml:line:11 |
| RS256 | jwt signature | jwt | — | internal | 67 (high) | yes | sample.jwt:line:1 |
| ML-KEM-768 | declared cryptographic algorithm | configuration | — | internal | 13 (low) | no | service.yaml:line:10 |
| 3DES | declared cryptographic algorithm | configuration | — | internal | 92 (critical) | no | sshd_config:line:4 |
| DH | ssh algorithm configuration | configuration | — | internal | 75 (high) | yes | sshd_config:line:3 |
| AES-256 | declared cryptographic algorithm | configuration | — | internal | 12 (low) | no | sshd_config:line:4 |
| LIBRARY-PYJWT | cryptographic library dependency | library | — | internal | 12 (low) | no | requirements.txt:line:2 |
| RSA | ssh algorithm configuration | configuration | — | internal | 65 (high) | yes | sshd_config:line:2 |
| ECDH | declared cryptographic algorithm | configuration | — | internal | 65 (high) | yes | nginx.conf:line:5 |
| AES-256 | declared cryptographic algorithm | configuration | — | internal | 12 (low) | no | nginx.conf:line:4 |
| RSA | tls certificate signature | configuration | — | internal | 65 (high) | yes | service.yaml:line:6 |
| TLS-1.2 | transport protocol | protocol | — | internal | 42 (medium) | no | nginx.conf:line:3 |

## Migration plan

| Priority | Phase | Kind | Target | Compatibility gate |
|---:|---|---|---|---|
| 100 | now | protocol-hardening | TLS 1.3 and currently approved classical algorithms | PQC does not compensate for a currently broken or deprecated primitive. |
| 100 | now | protocol-hardening | TLS 1.3 and currently approved classical algorithms | PQC does not compensate for a currently broken or deprecated primitive. |
| 92 | now | protocol-hardening | TLS 1.3 and currently approved classical algorithms | PQC does not compensate for a currently broken or deprecated primitive. |
| 75 | hybrid-transition | application-encapsulation | Explicit classical + ML-KEM-768 application protocol | This is experimental application encapsulation, not TLS negotiation or a claim of standards-track interoperability. |
| 67 | pqc-target | signature-transition | Versioned dual-verification profile, then ML-DSA-65 after ecosystem approval | The demo's ML-DSA application signature is not an ML-DSA TLS certificate and does not imply JOSE or browser support. |
| 65 | hybrid-transition | true-hybrid-tls | TLS 1.3 X25519MLKEM768 negotiated key agreement | True hybrid TLS negotiation is distinct from placing ML-KEM in an application message. No browser compatibility is inferred. |
| 65 | hybrid-transition | application-encapsulation | Explicit classical + ML-KEM-768 application protocol | This is experimental application encapsulation, not TLS negotiation or a claim of standards-track interoperability. |
| 65 | pqc-target | signature-transition | Versioned dual-verification profile, then ML-DSA-65 after ecosystem approval | The demo's ML-DSA application signature is not an ML-DSA TLS certificate and does not imply JOSE or browser support. |
| 65 | pqc-target | signature-transition | Versioned dual-verification profile, then ML-DSA-65 after ecosystem approval | The demo's ML-DSA application signature is not an ML-DSA TLS certificate and does not imply JOSE or browser support. |
| 62 | hybrid-transition | application-encapsulation | Explicit classical + ML-KEM-768 application protocol | This is experimental application encapsulation, not TLS negotiation or a claim of standards-track interoperability. |
| 62 | pqc-target | signature-transition | Versioned dual-verification profile, then ML-DSA-65 after ecosystem approval | The demo's ML-DSA application signature is not an ML-DSA TLS certificate and does not imply JOSE or browser support. |
| 42 | classic-hardening | standard-tls | TLS 1.3 with authenticated modern cipher suites | This step is standard TLS hardening; it is not post-quantum protection. |

## Interpretation boundaries

- Standard TLS means the TLS 1.3/X25519 baseline.
- True hybrid TLS requires an observed TLS key_share for `X25519MLKEM768`; naming ML-KEM in an application payload is not enough.
- Experimental application encapsulation is versioned separately and is not presented as TLS, an ML-DSA certificate, JOSE support, or browser compatibility.
