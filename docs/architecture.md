# Architecture and trust boundaries

The control plane has four independent paths so one component cannot turn an inference into
a cryptographic claim.

1. **Inventory path.** A bounded scanner reads explicitly selected local files. Network
   probes exist only on the CLI and require an exact host and port.
2. **Decision path.** A versioned registry and policy produce risk reasons and migration
   actions. There is no model-generated score.
3. **Measurement path.** OpenSSL creates TLS handshakes in memory; a wire parser reads the
   ServerHello group. A narrow native binding calls a pinned liboqs build.
4. **Presentation path.** JSON is the source of truth. Markdown, REST, and the dashboard
   render the same typed models.

```text
[untrusted scan tree] -- bounded reader --> [typed findings]
                                                |
                               registry + policy| (trusted, versioned)
                                                v
                                      [CBOM + plan] --> [atomic store]
                                                               |
[OpenSSL/liboqs native boundary] --> [validated metrics] -------+--> API/UI
```

## Native boundary

The benchmark accepts only liboqs 0.16.0 at a caller-provided installation prefix. It does
not search the global linker path or download at import time. Mechanism availability and
the library version are checked before use. Secret-key buffers are cleansed before the
native objects are freed.

OpenSSL is consumed through Python's standard `ssl` module. Because Python 3.12 cannot set
the composite group by name through `set_ecdh_curve`, the hybrid profile uses OpenSSL
3.5's default preference and validates every negotiated result on the wire. A wrong group
is an unavailable benchmark, never a downgraded hybrid data point.

## Persistence

Artifacts use content-derived IDs and atomic owner-only JSON writes. The demo store is
local filesystem state, not a multi-user database. The API has no authentication and must
remain loopback-bound or be placed behind an authenticated gateway.
