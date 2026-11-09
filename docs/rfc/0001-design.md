# RFC 0001: dfir-toolkit design

- **Status:** Accepted for M1
- **Author:** EquinoxWN
- **Created:** 2026-11-09

## Problem

When an incident has already happened, a responder has two early questions: *which machines in the
fleet look different?* and *what is running in the memory of the machine that looks worst?* The
standard tools answer both, Velociraptor for collection across endpoints and Volatility 3 for memory,
but each leaves work to the analyst:

- Velociraptor artifacts are YAML with embedded VQL. A typo, an unused parameter or a missing OS
  precondition is only found when a hunt runs, and nothing stops a "collection" artifact from calling
  `execve` or `http_client`, which changes the endpoint or the network during an investigation.
- A hunt over thousands of hosts returns hundreds of thousands of rows. The useful signal is what only
  a handful of hosts report (least frequency of occurrence), which has to be computed by hand.
- Volatility 3 prints raw plugin output. The checks analysts apply to it (a process found by pool
  scanning but missing from the process list, `lsass.exe` started by the wrong parent, a PE header in
  private RWX memory, Word starting PowerShell) are done by eye, one image at a time.

**Users:** incident responders and SOC analysts in small teams, and students learning DFIR.

### Critical-to-quality measures (Define)

| CTQ | Target for M1 | How it is measured |
|---|---|---|
| Unsafe or broken artifacts reach a hunt | 0: every defect class in the test table is rejected | `test_artifacts.py`, CI gate `dfir artifacts check` |
| Planted rare executables found by stacking | 100% found, 0 false rare entries, 5 seeds | `test_planted_executables_are_exactly_the_rare_set` |
| Stacking speed | 10,000 hosts (about 218,000 rows) in under 10 s on a laptop | `make bench`, recorded in `docs/results/m1.md` |
| Triage on the planted image | all 13 planted findings, nothing else | `test_injected_image_gives_exactly_the_planted_findings` |
| False positives on a clean baseline | 0 findings | `test_clean_image_gives_no_findings`, known-good look-alike names |
| Volatility failures | never a partial or unparseable output file | fake-Volatility failure tests and one real Volatility run |

## Goals

- M1: Velociraptor artifacts that collect evidence (processes with executable hashes, sockets, Linux
  persistence files, Windows Run keys, Linux logs as uploaded evidence), a static gate that rejects
  unsafe or broken artifacts, and fleet stacking of hunt and collection results.
- M1: Volatility 3 runner and triage rules that flag hidden, masquerading and injected processes,
  with MITRE ATT&CK technique ids, as JSON and Markdown reports.
- M2: Plaso super-timeline and Timesketch; playbooks for common incidents.
- M3: playbooks exercised on public challenge images, with case reports.

## Non-goals

- Running a Velociraptor server or a hosted service.
- Acquiring memory (WinPmem, AVML) or shipping memory images.
- Any offensive capability: artifacts only read and upload evidence; test data is synthetic.

## Proposed design

```
artifacts/*.yaml ──> dfir artifacts check (static gate) ──> Velociraptor hunt / offline collector
                                                                │
              collection zips (results/<Artifact>.json) or hunt JSON-lines export
                                                                │
                                            dfir hunt stack ──> rare keys per artifact (JSON, Markdown)

memory image ──> dfir memory run (Volatility 3 child process, timeout, atomic outputs)
                     pslist, psscan, malfind, netscan, cmdline as JSON
                                                                │
                                            dfir memory triage ──> findings with ATT&CK ids
```

- **Artifact gate (`artifacts.py`).** YAML is loaded with `safe_load` and a size limit. Names follow
  `Custom.DFIR.<Generic|Windows|Linux>.<Name>`; Windows and Linux artifacts need a matching
  `OS = '...'` precondition; parameters must be identifiers of a known type with a default that fits
  the type and must be used by a query. VQL is scanned after removing strings and comments; every call
  must be on a read-only allowlist, and known endpoint- or network-changing calls get a specific error.
- **Stacking (`hunt.py`).** Rows are streamed from JSON lines or from zip members without extracting
  (each line and member is size-bounded, decompression is capped). Each artifact has a stack key (for
  processes: executable path and SHA-256). The report counts distinct hosts per key and keeps keys seen
  on at most `max(1, floor(fraction x hosts))` hosts, sorted with temp-directory paths first.
- **Memory (`volrunner.py`, `memory.py`).** Volatility 3 runs as a child process with the JSON renderer
  and a timeout; output goes to a partial file that is renamed into place only after it parses. Triage
  flattens the JSON tree and applies rules: hidden process (psscan minus pslist, not exited), unexpected
  parent of core processes, duplicate singletons (lsass, services, wininit), names within two edits of a
  core name (with a known-good list), document application starting a shell, PE header or code in
  private RWX memory, encoded/hidden/download PowerShell, core binaries outside System32, and external
  established connections from processes another rule flagged.

## Alternatives considered

| Option | Why not (yet) |
|---|---|
| Stack inside Velociraptor with a server-side VQL notebook | Needs a running server and its datastore; the offline-collector and hunt-export path works with no server, and the same zips can be stacked from any machine. A notebook remains a good M2 addition. |
| Validate artifacts only by loading them into Velociraptor | Catches syntax errors but accepts `execve` and unused parameters; the binary is 30 MB per platform. The static gate runs in milliseconds and CI still loads the artifacts into a real Velociraptor. |
| Import Volatility 3 as a library and walk its TreeGrid in-process | Tighter coupling to an internal API, a crash or hang takes the toolkit down, and the Volatility Software License would bind the core package. The child process plus JSON renderer keeps Volatility optional and swappable (ADR 0003). |
| Use `windows.malware.psxview` / `pstree` output directly | psxview covers hidden processes only; the five-plugin set covers the M1 rules and keeps runs short. |

## Measurement plan (Measure, Analyze, Control)

- Tests run locally and in CI (`make test`); the counts and every test file are listed in
  `docs/results/m1.md`.
- Stacking speed: `make bench` on 10,000 synthetic hosts, CPU and wall time recorded.
- Mutation testing by hand on the core functions, recorded in `docs/quality/2026-11-01.md`.
- Control: CI runs lint, strict types, the artifact gate, tests, the bench, pip-audit, and a
  Velociraptor collection from the runner with the repo's artifacts.

## Milestones

- **M1:** Velociraptor artifacts collect evidence from endpoints at scale. Volatility 3 analyzes memory images for malicious processes and injected code.
- **M2:** Plaso builds a super-timeline, and Timesketch lets you explore it. Playbooks guide the response to common incidents.
- **M3:** Each playbook is exercised on a public challenge image. Case reports document the findings, timeline and indicators of compromise.

## Risks and open questions

- The triage fixtures are synthetic: they match Volatility 3 2.28's column names (checked by a test
  against the installed plugins) but not the noise of a real image. M3 runs the rules on public
  challenge images and will tune false positives.
- The VQL scanner is lexical, not a parser: a call built dynamically could hide from it. The allowlist
  keeps the surface small and CI loads every artifact into Velociraptor.
- Least frequency of occurrence misses an implant present on many hosts; it is a triage order, not a
  verdict.
