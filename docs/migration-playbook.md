# Migration playbook

## Phase 0 — inventory and ownership

Establish an owner, business purpose, peer population, confidentiality duration, rotation
process, and rollback for each cryptographic asset. Treat low-confidence text findings as
questions to validate, not automatic production changes.

## Phase 1 — classical hardening

Remove broken primitives and deprecated protocols before introducing PQC complexity. Move
to TLS 1.3, approved key sizes, sound certificate validation, and explicit algorithm
policies. Measure the remaining fallback population.

## Phase 2 — hybrid transition

For TLS key agreement, canary a stack that actually negotiates X25519MLKEM768 and record the
ServerHello group. Make classical fallback visible and policy-controlled. For non-TLS
protocols, any combined classical/PQC envelope needs version negotiation, downgrade
binding, independent keys, canonical transcripts, and a threat model. It remains an
application protocol, not “hybrid TLS”.

## Phase 3 — PQC target

Roll verifiers before signers, design trust-anchor and revocation lifecycle, and retain
dual-verification evidence until all consumers are ready. Adopt pure-PQC protocol profiles
only when the relevant ecosystem specifications and implementations support them; do not
invent identifiers or infer browser support from a library benchmark.

## Change evidence

Each migration action includes prerequisites, acceptance tests, a rollback, and a
compatibility note. Capture before/after CBOMs and benchmark reports. A successful change
reduces high-risk findings without silently increasing failed business transactions.
