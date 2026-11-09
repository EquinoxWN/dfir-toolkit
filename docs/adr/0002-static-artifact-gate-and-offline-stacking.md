# ADR 0002: A static artifact gate and stacking outside Velociraptor

- **Status:** Accepted

## Context

Artifacts run on many endpoints at once during an incident. A broken artifact wastes a hunt; an
artifact that calls `execve` or `http_client` changes the evidence or the network it is meant to
observe. Velociraptor loads any syntactically valid artifact. Stacking hunt results can be done in a
Velociraptor server notebook, but that needs a running server.

## Decision

1. Every artifact passes `dfir artifacts check` before it is used: naming, OS precondition, typed and
   used parameters, and a read-only allowlist of VQL calls. CI also loads the artifacts into a pinned
   Velociraptor release and collects from the runner.
2. Stacking runs in Python over collection zips and hunt exports, never extracting the zips.

## Consequences

- Mistakes are caught in milliseconds, before a hunt; adding a new VQL function means a deliberate
  edit of the allowlist (a review point), which is friction for authors.
- The lexical scanner can be fooled by dynamically built calls; the allowlist and the CI load reduce,
  but do not remove, that risk.
- Stacking works on any machine with the exported files, offline, which suits a responder working from
  copied evidence; it does not see live server state, and very large hunts are bounded by one Python
  process (about 218,000 rows in 3 to 4 s on the author's laptop).
