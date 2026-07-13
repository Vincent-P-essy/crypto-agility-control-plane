# Contributing

Changes are welcome when they preserve evidence quality and explicit scope boundaries.

## Development loop

```bash
uv sync --extra dev --frozen
make lint
make typecheck
make test
```

For native or TLS-hybrid changes, also build the pinned library and run integration tests:

```bash
./scripts/build-liboqs.sh .local/oqs
OQS_INSTALL_PATH="$PWD/.local/oqs" \
LD_LIBRARY_PATH="$PWD/.local/oqs/lib" \
uv run pytest -m integration
```

## Evidence rules

- Never add a timing, size, compatibility result, or success flag that was not measured.
- A missing primitive or negotiated group must produce an unavailable/failed run.
- Keep standard TLS, true hybrid TLS negotiation, and application encapsulation distinct.
- Do not infer browser or ecosystem support from an OpenSSL-to-OpenSSL test.
- Fixtures must be synthetic. Never commit private operational keys, tokens, or customer data.
- A schema, algorithm-registry, risk-policy, native ABI, source checksum, or group-ID change
  requires tests, updated golden evidence, and a migration/security review.

Pull requests should explain the threat model, compatibility impact, reproduction command,
and limitations. Keep commits focused and preserve the lockfile.
