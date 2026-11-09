# ADR 0003: Run Volatility 3 as a child process and triage its JSON

- **Status:** Accepted

## Context

The triage rules need Volatility 3 plugin output. Volatility can be imported as a library (walking its
TreeGrid objects) or run as a command with `-r json`. Memory analysis of a large image can take
minutes per plugin, and plugins can fail or hang on damaged images. Volatility 3 is published under the
Volatility Software License 1.0, not an OSI licence.

## Decision

Run each plugin as a child process (`python -c "... volatility3.cli.main()"`) with the JSON renderer,
a per-plugin timeout and an in-repo cache path. Output is written to a partial file and renamed into
place only after it parses. The triage rules read only the JSON files, and Volatility 3 is an optional
extra (`pip install -e ".[vol]"`).

## Consequences

- A hang or crash in Volatility becomes a `VolatilityError` with the end of its stderr; no partial
  output file is left (tested with a fake Volatility and with the real one on a non-image).
- Triage can run on JSON produced elsewhere (another analyst's machine, a CI job, a different
  Volatility version), and the core package does not depend on Volatility's licence.
- Process start-up costs about 2 to 4 s per plugin, negligible next to plugin run times on real images.
- The JSON column names are an interface the toolkit does not control; a test checks that the installed
  Volatility 3 still declares every column the rules read.
