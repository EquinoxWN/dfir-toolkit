# Contributing

Thanks for helping. This is a Python project; issues and pull requests are welcome.

## Set up and check your change

Needs Python 3.11+. Volatility 3 is installed as the `vol` extra; Velociraptor runs in CI only.
Caches and virtual environments stay in git-ignored folders inside the repo.

```bash
make setup   # install the package with the dev and vol extras
make lint    # ruff, ruff format, mypy --strict, artifact gate
make test    # full test suite
make audit   # known-vulnerability check (as in CI)
```

A pull request is ready when `make lint` and `make test` pass and CI is green.

## Guidelines

- New artifacts go in `artifacts/`, are named `Custom.DFIR.<Generic|Windows|Linux>.<Name>`, carry an
  OS precondition, use every parameter they declare, and call only read-only VQL; `dfir artifacts
  check` enforces this. Add a stack key for it in `hunt.STACK_KEYS`.
- New triage rules need a test that fires and one that does not (a known-good look-alike), plus an
  ATT&CK technique id.
- Test data stays synthetic: no real malware, memory images, hostnames or secrets.
- Keep each change focused; significant design changes need an ADR in `docs/adr/`.
- Keep function comments to one short phrase; let names and tests explain the rest.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your work is released under the [MIT License](LICENSE).
