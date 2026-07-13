# Security policy

This repository is a defensive inventory and interoperability laboratory. Do not place
production keys, tokens, certificates, or unrestricted filesystem roots in the demo.

For a suspected vulnerability, open a private security advisory in the GitHub repository.
Include the affected version, reproducible steps, impact, and any proposed mitigation.
Please do not include live credentials or customer data.

The `main` branch is supported. Native cryptographic dependencies are pinned and reviewed
separately from Python dependencies. A change to algorithm semantics, group identifiers,
native ABI, source checksum, or benchmark validation requires a security-focused review.
