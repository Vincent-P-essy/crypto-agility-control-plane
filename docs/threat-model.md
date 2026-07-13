# Threat model

## Assets

- private key material and tokens encountered during inventory;
- integrity of CBOM evidence, risk reasons, migration plans, and benchmark results;
- native process integrity at the OpenSSL/liboqs boundary;
- allowed filesystem roots and explicit endpoint scope.

## Adversaries and failure modes

An untrusted repository may contain huge files, symlinks, malformed PEM/JWT data, terminal
control characters, or strings crafted to look cryptographic. A remote endpoint may stall,
present an invalid certificate, or negotiate a classical fallback. A build dependency may
change or the wrong liboqs ABI may be loaded. A dashboard value may contain HTML.

## Controls

- no symlink traversal; bounded file size; ignored dependency/build directories;
- parser failures become absent/low-confidence evidence, not execution;
- no shell invocation for file content; `ssh-keyscan` receives a fixed argument vector;
- TLS verification defaults on and endpoint probes are never exposed by the HTTP API;
- no raw secrets, token payloads, PEM data, or configuration excerpts in output;
- Pydantic forbids unknown fields in persisted domain models;
- dashboard renders untrusted fields with `textContent`; CSP denies inline scripts;
- exact liboqs version/mechanism gate and source checksum;
- TLS group observed in ServerHello; a mismatch discards hybrid metrics;
- output is atomic and mode 0600; API scan roots are allowlisted and resolved.

## Accepted risks

The scanner must read selected files in process memory to classify them. It is not isolated
from malicious native parser vulnerabilities. Run it with a low-privilege account against
untrusted input. The local API has no identity layer. Process RSS includes interpreter and
allocator behaviour. Text matches can be commented or unreachable and therefore carry a
lower confidence than parsed objects.
