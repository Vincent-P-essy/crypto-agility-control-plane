# CBOM schema 1.0.0

`schemas/cbom-1.0.0.schema.json` defines the document envelope. Runtime models are stricter
about individual fields and reject unknown properties.

## Identity

`document_id` is `urn:cbom:sha256:<digest>`. The digest covers source label, policy, ordered
findings, assessments, and migration plan, but not `generated_at`. Re-running the same
evidence and policy therefore produces the same identity while retaining an honest run
timestamp.

## Evidence privacy

An evidence item contains:

- `source`: relative file or explicit endpoint URI;
- `locator`: line, certificate, or negotiated-session location;
- `detector`: parser/probe that produced the result;
- `excerpt_hash`: SHA-256 of normalized matched text;
- `confidence`: `0..1`.

Neither the excerpt nor secret value is serialized. Public-key and certificate
fingerprints are separate metadata because they are intended correlation identifiers.

## Evolution

Breaking field or semantic changes require a new schema version. Registry and policy
versions are embedded independently because a CBOM can be re-assessed without rescanning.
