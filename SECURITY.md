# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(`https://github.com/EquinoxWN/dfir-toolkit/security/advisories/new`). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer
within 7 days. Fixes are released as soon as they are ready, and you are credited unless you ask
not to be.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.

## Scope

- **In scope:** an artifact that changes an endpoint or reaches the network although the static gate
  accepted it; unsafe parsing of collection zips, hunt exports or Volatility output (path traversal,
  unbounded memory, zip bombs); a triage rule that silently drops evidence.
- **Out of scope:** vulnerabilities in Velociraptor or Volatility 3 themselves (report those upstream).

## What this repository is and is not

The toolkit is defensive. The artifacts only read (process list, sockets, files, registry) and upload
evidence into the collection; the static gate rejects `execve`, `rm`, `copy`, `http_client` and every
VQL call that is not on a read-only allowlist. All test data is synthetic: the memory fixtures are
hand-written Volatility JSON, the fleet is generated, and no real malware, credential or memory image
is shipped.

## How this repository protects itself

- Every GitHub Action is pinned to a full commit SHA, and workflows run with read-only
  permissions and without persisted credentials. The Velociraptor binary used in CI is a pinned
  release whose SHA-256 is checked before it runs.
- Dependabot update pull requests are paused (`open-pull-requests-limit: 0`) so the repository keeps a single `main` branch; dependencies are updated by hand and checked by the CI audit.
- CI runs lint, strict types, tests and a known-vulnerability check (pip-audit) on every push and pull request.
