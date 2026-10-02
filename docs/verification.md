# Execution record

Local execution of `crypto-agility scan fixtures --out ./runtime/crypto-example`. The input and output shown come from the repository example or test fixtures.

- `crypto-agility scan fixtures --out ./runtime/crypto-example` — exit 0.

The image renders the captured terminal output. [Full transcript](screenshots/execution.txt).

Latest local test output:

```text
........s.......ss........                                               [100%]
=============================== warnings summary ===============================
../../python-env/lib/python3.12/site-packages/fastapi/testclient.py:1
  ./python-env/lib/python3.12/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
=========================== short test summary info ============================
SKIPPED [1] tests/test_demo.py:59: OQS_INSTALL_PATH is not configured; no integration result is fabricated
SKIPPED [2] tests/test_native_oqs.py:16: OQS_INSTALL_PATH is not configured; no native metric is fabricated
23 passed, 3 skipped, 1 warning in 0.65s
```

This record covers the local commands and fixtures shown. External services and deployment remain unverified unless explicitly listed.
