"""The ``dfir`` command line: check artifacts, stack hunt results, run and triage Volatility."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from dfir_toolkit import artifacts, hunt, memory, synth, volrunner
from dfir_toolkit._io import InputError, atomic_write_text


def _fraction(text: str) -> float:
    """argparse type: a float strictly between 0 and 1."""
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from exc
    if not 0 < value < 1:
        raise argparse.ArgumentTypeError("must be between 0 and 1 (exclusive)")
    return value


def _int_at_least(minimum: int) -> Callable[[str], int]:
    """argparse type: an integer of at least minimum."""

    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"not an integer: {text!r}") from exc
        if value < minimum:
            raise argparse.ArgumentTypeError(f"must be at least {minimum}")
        return value

    return parse


def _positive_float(text: str) -> float:
    """argparse type: a number above 0."""
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError("must be above 0")
    return value


def cmd_artifacts_check(args: argparse.Namespace) -> int:
    """Validate the artifact directory."""
    found, problems = artifacts.check_directory(Path(args.directory))
    for a in found:
        print(f"ok   {a.name} ({a.os}, {len(a.parameters)} parameters, calls: {', '.join(sorted(a.calls))})")
    for p in problems:
        print(f"FAIL {p}", file=sys.stderr)
    print(f"{len(found)} artifacts valid, {len(problems)} problems")
    return 1 if problems else 0


def cmd_hunt_stack(args: argparse.Namespace) -> int:
    """Stack one artifact's results across hosts and report the rare values."""
    started = time.monotonic()
    rows = hunt.read_results([Path(p) for p in args.inputs], args.artifact, args.host)
    artifact = args.artifact
    if artifact is None:
        rows_list = list(rows)
        names = sorted({r.artifact for r in rows_list})
        if len(names) != 1:
            raise InputError(f"inputs hold {len(names)} artifacts ({', '.join(names)}); pick one with --artifact")
        artifact = names[0]
        rows = iter(rows_list)
    report = hunt.stack(rows, artifact, args.rare_fraction)
    elapsed = time.monotonic() - started
    if args.json:
        atomic_write_text(Path(args.json), json.dumps(report.to_json(), indent=2) + "\n")
    if args.md:
        atomic_write_text(Path(args.md), hunt.report_markdown(report))
    print(
        f"{report.artifact}: {report.hosts} hosts, {report.rows} rows, {report.distinct_keys} distinct keys, "
        f"{len(report.rare)} rare (<= {report.max_hosts} hosts), {elapsed:.2f} s"
    )
    for e in report.rare[: args.show]:
        flag = " [suspicious path]" if e.suspicious_path else ""
        print(f"  {e.count} host(s): {' | '.join(e.key)}{flag}")
    return 0


def cmd_hunt_synth(args: argparse.Namespace) -> int:
    """Write a synthetic fleet hunt export."""
    fleet = synth.generate(args.hosts, args.seed)
    atomic_write_text(Path(args.out), "".join(synth.to_jsonl(fleet.rows)))
    print(f"{len(fleet.rows)} rows for {fleet.hosts} hosts written to {args.out}")
    return 0


def cmd_memory_run(args: argparse.Namespace) -> int:
    """Run Volatility 3 plugins on an image."""
    runs = volrunner.run_plugins(Path(args.image), Path(args.outdir), tuple(args.plugins), args.timeout, args.offline)
    for r in runs:
        print(f"{r.plugin}: {r.rows} rows in {r.seconds:.1f} s -> {r.output}")
    return 0


def cmd_memory_triage(args: argparse.Namespace) -> int:
    """Apply the triage rules to a directory of plugin JSON files."""
    outputs = memory.load_directory(Path(args.directory))
    findings = memory.triage(outputs)
    if args.json:
        payload = {
            "source": args.directory,
            "plugins": sorted(outputs),
            "counts": memory.summary_counts(findings),
            "findings": [f.to_json() for f in findings],
        }
        atomic_write_text(Path(args.json), json.dumps(payload, indent=2) + "\n")
    if args.md:
        atomic_write_text(Path(args.md), memory.report_markdown(findings, args.directory))
    counts = memory.summary_counts(findings)
    print(
        f"{len(findings)} findings ({counts['high']} high, {counts['medium']} medium, {counts['low']} low) from {', '.join(sorted(outputs))}"
    )
    for f in findings:
        print(f"  {f.severity:<6} pid {f.pid:<6} {f.process:<16} {f.rule} ({f.technique})")
    if args.fail_on and any(memory.SEVERITY_ORDER[f.severity] <= memory.SEVERITY_ORDER[args.fail_on] for f in findings):
        return 3
    return 0


def build_parser() -> argparse.ArgumentParser:
    """The argument parser for all subcommands."""
    parser = argparse.ArgumentParser(prog="dfir", description=__doc__)
    sub = parser.add_subparsers(dest="group", required=True)

    art = sub.add_parser("artifacts", help="Velociraptor artifacts").add_subparsers(dest="cmd", required=True)
    check = art.add_parser("check", help="validate artifact YAML files")
    check.add_argument("directory", nargs="?", default="artifacts")
    check.set_defaults(func=cmd_artifacts_check)

    hnt = sub.add_parser("hunt", help="hunt and collection results").add_subparsers(dest="cmd", required=True)
    st = hnt.add_parser("stack", help="least-frequency stacking across hosts")
    st.add_argument("inputs", nargs="+", help="collection zips or JSON-lines hunt exports")
    st.add_argument("--artifact", choices=sorted(hunt.STACK_KEYS))
    st.add_argument("--host", help="host name for inputs that do not carry one")
    st.add_argument(
        "--rare-fraction", type=_fraction, default=0.01, help="rare = on at most this share of hosts (default 0.01)"
    )
    st.add_argument("--show", type=_int_at_least(0), default=20, help="rare entries to print")
    st.add_argument("--json", help="write the report as JSON")
    st.add_argument("--md", help="write the report as Markdown")
    st.set_defaults(func=cmd_hunt_stack)
    sy = hnt.add_parser("synth", help="write a synthetic fleet hunt export")
    sy.add_argument("--hosts", type=_int_at_least(1), default=1000)
    sy.add_argument("--seed", type=int, default=0)
    sy.add_argument("--out", required=True)
    sy.set_defaults(func=cmd_hunt_synth)

    mem = sub.add_parser("memory", help="Volatility 3 memory analysis").add_subparsers(dest="cmd", required=True)
    run = mem.add_parser("run", help="run Volatility 3 plugins on an image")
    run.add_argument("--image", required=True)
    run.add_argument("--outdir", required=True)
    run.add_argument("--plugins", nargs="+", choices=sorted(volrunner.VOL_PLUGINS), default=list(volrunner.VOL_PLUGINS))
    run.add_argument("--timeout", type=_positive_float, default=1800.0, help="seconds per plugin")
    run.add_argument("--offline", action="store_true", help="do not download symbol tables")
    run.set_defaults(func=cmd_memory_run)
    tri = mem.add_parser("triage", help="flag suspicious processes from plugin JSON")
    tri.add_argument("directory", help="folder with pslist.json and optionally psscan, malfind, netscan, cmdline")
    tri.add_argument("--json", help="write findings as JSON")
    tri.add_argument("--md", help="write findings as Markdown")
    tri.add_argument(
        "--fail-on", choices=["high", "medium", "low"], help="exit 3 when a finding at or above this severity exists"
    )
    tri.set_defaults(func=cmd_memory_triage)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the exit code."""
    args = build_parser().parse_args(argv)
    try:
        code: int = args.func(args)
    except (InputError, volrunner.VolatilityError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return code


if __name__ == "__main__":
    raise SystemExit(main())
