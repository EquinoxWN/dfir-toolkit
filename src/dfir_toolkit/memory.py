"""Triage of Volatility 3 JSON output: hidden, masquerading and injected processes.

Input is the ``-r json`` output of five Windows plugins (pslist, psscan, malfind, netscan,
cmdline). Each rule is a well-known analyst check, mapped to a MITRE ATT&CK technique.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from dfir_toolkit._io import InputError, read_bounded

Severity = Literal["high", "medium", "low"]
SEVERITY_ORDER: dict[str, int] = {"high": 0, "medium": 1, "low": 2}
MAX_PLUGIN_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_ROWS = 2_000_000

# Columns each plugin's JSON must carry (checked against the installed Volatility 3 in a test).
REQUIRED_COLUMNS: dict[str, frozenset[str]] = {
    "pslist": frozenset({"PID", "PPID", "ImageFileName", "CreateTime", "ExitTime"}),
    "psscan": frozenset({"PID", "PPID", "ImageFileName", "CreateTime", "ExitTime"}),
    "malfind": frozenset({"PID", "Process", "Start VPN", "Protection", "PrivateMemory", "Hexdump"}),
    "netscan": frozenset({"Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID", "Owner"}),
    "cmdline": frozenset({"PID", "Process", "Args"}),
}
PLUGINS = tuple(REQUIRED_COLUMNS)

# Expected parent of core Windows processes (child -> parent image name).
EXPECTED_PARENT = {
    "services.exe": "wininit.exe",
    "lsass.exe": "wininit.exe",
    "lsaiso.exe": "wininit.exe",
    "svchost.exe": "services.exe",
    "spoolsv.exe": "services.exe",
    "taskhostw.exe": "svchost.exe",
    "runtimebroker.exe": "svchost.exe",
}
SINGLETONS = frozenset({"lsass.exe", "services.exe", "wininit.exe", "lsaiso.exe"})
CORE_NAMES = frozenset(EXPECTED_PARENT) | SINGLETONS | {"smss.exe", "csrss.exe", "winlogon.exe", "explorer.exe"}
# Real Windows process names that are within two edits of a core name.
KNOWN_GOOD = frozenset(
    {"sihost.exe", "taskhost.exe", "taskhostex.exe", "conhost.exe", "dllhost.exe", "lsm.exe", "wlms.exe", "svchost.exe"}
)
DOCUMENT_APPS = frozenset(
    {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "mspub.exe", "onenote.exe"}
)
SHELLS = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "bitsadmin.exe",
        "certutil.exe",
    }
)
SYSTEM32_RE = re.compile(r"^\\?(\\\?\?\\)?[a-z]:\\windows\\(system32|syswow64)\\", re.I)
ENCODED_PS_RE = re.compile(r"\s-(e|ec|en|enc|enco|encod|encode|encodedc|encodedcommand)\s", re.I)
DOWNLOAD_CRADLE_RE = re.compile(
    r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer", re.I
)
HIDDEN_WINDOW_RE = re.compile(r"\s-(w|wi|win|windowstyle)\s+(h|hidden)\b", re.I)
# Internal ranges; everything else (documentation ranges included) counts as external.
INTERNAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)
_LIST_START_RE = re.compile(r"^[ \t]*\[", re.M)  # the JSON list starts on its own line, after the banner
EXEC_WRITE = re.compile(r"PAGE_EXECUTE_(READWRITE|WRITECOPY)")


@dataclass(frozen=True)
class Finding:
    """One suspicious observation with the evidence behind it."""

    rule: str
    severity: Severity
    pid: int
    process: str
    technique: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        """A JSON-ready dict."""
        return {
            "rule": self.rule,
            "severity": self.severity,
            "pid": self.pid,
            "process": self.process,
            "technique": self.technique,
            "summary": self.summary,
            "evidence": self.evidence,
        }


def parse_vol_json(text: str, plugin: str, where: str = "<input>") -> list[dict[str, Any]]:
    """Flatten Volatility 3 JSON (a tree of rows with __children) into a list of rows."""
    if plugin not in REQUIRED_COLUMNS:
        raise ValueError(f"unknown plugin {plugin!r}; known: {', '.join(PLUGINS)}")
    start = next((m.start() for m in _LIST_START_RE.finditer(text)), -1)
    if start < 0:
        raise InputError(f"{where}: no JSON list in Volatility output")
    try:
        tree = json.loads(text[start:])
    except json.JSONDecodeError as exc:
        raise InputError(f"{where}: Volatility output is not JSON ({exc})") from exc
    if not isinstance(tree, list):
        raise InputError(f"{where}: expected a JSON list of rows")
    rows: list[dict[str, Any]] = []
    stack: list[Any] = list(reversed(tree))
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            raise InputError(f"{where}: row {len(rows)} is not an object")
        missing = REQUIRED_COLUMNS[plugin] - node.keys()
        if missing:
            raise InputError(f"{where}: {plugin} row {len(rows)} lacks {sorted(missing)}")
        if not isinstance(node.get("PID"), int) or isinstance(node.get("PID"), bool):
            raise InputError(f"{where}: {plugin} row {len(rows)} has a non-integer PID")
        children = node.get("__children", [])
        children = [] if children is None else children
        if not isinstance(children, list):
            raise InputError(f"{where}: __children must be a list")
        rows.append({k: v for k, v in node.items() if k != "__children"})
        if len(rows) > MAX_ROWS:
            raise InputError(f"{where}: more than {MAX_ROWS} rows")
        stack.extend(reversed(children))
    return rows


def load_plugin_output(path: Path, plugin: str) -> list[dict[str, Any]]:
    """Read and parse one plugin's JSON file."""
    raw = read_bounded(path, MAX_PLUGIN_OUTPUT_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(f"{path}: not UTF-8 ({exc})") from exc
    return parse_vol_json(text, plugin, str(path))


def load_directory(directory: Path) -> dict[str, list[dict[str, Any]]]:
    """Every <plugin>.json present in a directory; pslist is required."""
    out = {p: load_plugin_output(directory / f"{p}.json", p) for p in PLUGINS if (directory / f"{p}.json").is_file()}
    if "pslist" not in out:
        raise InputError(f"{directory}: pslist.json is required")
    return out


def _name(row: Mapping[str, Any], column: str = "ImageFileName") -> str:
    """Lower-case process name from a row."""
    value = row.get(column)
    return value.lower() if isinstance(value, str) else ""


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (small strings only)."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _process_rules(pslist: list[dict[str, Any]], psscan: list[dict[str, Any]] | None) -> list[Finding]:
    """Hidden, unexpected-parent, duplicate-singleton, masquerade and document-spawns-shell rules."""
    findings: list[Finding] = []
    live = [r for r in pslist if r.get("ExitTime") is None]
    by_pid = {r["PID"]: r for r in pslist}
    if psscan is not None:
        listed = set(by_pid)
        for r in psscan:
            if r["PID"] not in listed and r.get("ExitTime") is None and r["PID"] not in (0, 4):
                findings.append(
                    Finding(
                        "hidden-process",
                        "high",
                        r["PID"],
                        _name(r),
                        "T1014",
                        "running process found by pool scanning but missing from the active process list (unlinked)",
                        {"ppid": r["PPID"], "create_time": r.get("CreateTime")},
                    )
                )
    for r in live:
        name = _name(r)
        parent = by_pid.get(r["PPID"])
        want = EXPECTED_PARENT.get(name)
        if want and parent is not None and _name(parent) != want:
            findings.append(
                Finding(
                    "unexpected-parent",
                    "high",
                    r["PID"],
                    name,
                    "T1036",
                    f"{name} should be started by {want}, not {_name(parent)}",
                    {"ppid": r["PPID"], "parent": _name(parent)},
                )
            )
        if parent is not None and _name(parent) in DOCUMENT_APPS and name in SHELLS:
            findings.append(
                Finding(
                    "document-spawned-shell",
                    "high",
                    r["PID"],
                    name,
                    "T1204.002",
                    f"{_name(parent)} started {name}: typical of a malicious document",
                    {"ppid": r["PPID"], "parent": _name(parent)},
                )
            )
        if name not in CORE_NAMES and name not in KNOWN_GOOD:
            near = sorted(c for c in CORE_NAMES if _edit_distance(name, c) <= 2)
            if near:
                findings.append(
                    Finding(
                        "masquerading-name",
                        "high",
                        r["PID"],
                        name,
                        "T1036.005",
                        f"{name} is one or two letters away from {near[0]}",
                        {"looks_like": near[0]},
                    )
                )
    counts = Counter(_name(r) for r in live)
    for name in sorted(SINGLETONS):
        if counts[name] > 1:
            pids = sorted(r["PID"] for r in live if _name(r) == name)
            for pid in pids:
                findings.append(
                    Finding(
                        "duplicate-singleton",
                        "high",
                        pid,
                        name,
                        "T1036",
                        f"{counts[name]} instances of {name}; Windows runs exactly one",
                        {"pids": pids},
                    )
                )
    return findings


def _malfind_rules(malfind: list[dict[str, Any]]) -> list[Finding]:
    """Private executable-writable memory, worse when it starts with a PE header."""
    findings: list[Finding] = []
    for r in malfind:
        protection = str(r.get("Protection") or "")
        if not EXEC_WRITE.search(protection) or r.get("PrivateMemory") != 1:
            continue
        hexdump = str(r.get("Hexdump") or "").replace(" ", "").replace("\n", "").lower()
        start = r.get("Start VPN")
        evidence = {"start_vpn": hex(start) if isinstance(start, int) else start, "protection": protection}
        if hexdump.startswith("4d5a"):
            findings.append(
                Finding(
                    "injected-pe",
                    "high",
                    r["PID"],
                    _name(r, "Process"),
                    "T1055.001",
                    "private RWX memory starts with an MZ header: a PE image loaded without the loader",
                    evidence,
                )
            )
        elif hexdump and set(hexdump) != {"0"}:
            findings.append(
                Finding(
                    "injected-code",
                    "medium",
                    r["PID"],
                    _name(r, "Process"),
                    "T1055",
                    "private RWX memory holding code that no file on disk backs",
                    evidence,
                )
            )
    return findings


def _cmdline_rules(cmdline: list[dict[str, Any]]) -> list[Finding]:
    """Encoded or download-cradle PowerShell, and system binaries run from elsewhere."""
    findings: list[Finding] = []
    for r in cmdline:
        args = r.get("Args")
        if not isinstance(args, str):
            continue
        name = _name(r, "Process")
        padded = f" {args} "
        if name in {"powershell.exe", "pwsh.exe"}:
            hits = [
                label
                for label, rx in (
                    ("encoded", ENCODED_PS_RE),
                    ("download", DOWNLOAD_CRADLE_RE),
                    ("hidden-window", HIDDEN_WINDOW_RE),
                )
                if rx.search(padded)
            ]
            if hits:
                findings.append(
                    Finding(
                        "suspicious-powershell",
                        "high" if len(hits) > 1 else "medium",
                        r["PID"],
                        name,
                        "T1059.001",
                        "PowerShell started with " + ", ".join(hits) + " options",
                        {"indicators": hits, "args": args[:512]},
                    )
                )
        image = args.strip().strip('"').split('"', 1)[0].split(" ", 1)[0] if args.strip() else ""
        if name in EXPECTED_PARENT and "\\" in image and not SYSTEM32_RE.match(image):
            findings.append(
                Finding(
                    "system-binary-wrong-path",
                    "high",
                    r["PID"],
                    name,
                    "T1036.005",
                    f"{name} runs from {image}, outside System32",
                    {"image": image},
                )
            )
    return findings


def _is_external(addr: Any) -> bool:
    """True unless the address is internal (RFC 1918, CGNAT, loopback, link-local, ULA) or unspecified."""
    try:
        ip = ipaddress.ip_address(str(addr))
    except ValueError:
        return False
    if ip.is_unspecified or ip.is_multicast:
        return False
    return not any(ip in net for net in INTERNAL_NETS if net.version == ip.version)


def _network_rules(netscan: list[dict[str, Any]], flagged: dict[int, str]) -> list[Finding]:
    """External connections from processes another rule already flagged."""
    findings: list[Finding] = []
    for r in netscan:
        pid = r["PID"]
        if pid in flagged and str(r.get("State")) == "ESTABLISHED" and _is_external(r.get("ForeignAddr")):
            findings.append(
                Finding(
                    "flagged-process-external-connection",
                    "high",
                    pid,
                    flagged[pid],
                    "T1071",
                    f"flagged process talks to {r['ForeignAddr']}:{r['ForeignPort']}",
                    {"remote": f"{r['ForeignAddr']}:{r['ForeignPort']}", "proto": r.get("Proto")},
                )
            )
    return findings


def triage(outputs: Mapping[str, list[dict[str, Any]]]) -> list[Finding]:
    """Run every rule whose plugin output is present; findings sorted by severity then PID."""
    if "pslist" not in outputs:
        raise InputError("pslist output is required for triage")
    findings = _process_rules(outputs["pslist"], outputs.get("psscan"))
    findings += _malfind_rules(outputs.get("malfind") or [])
    findings += _cmdline_rules(outputs.get("cmdline") or [])
    flagged: dict[int, str] = {}
    for f in findings:
        flagged.setdefault(f.pid, f.process)
    findings += _network_rules(outputs.get("netscan") or [], flagged)
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.pid, f.rule))


def summary_counts(findings: Iterable[Finding]) -> dict[str, int]:
    """Number of findings per severity."""
    c: Counter[str] = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in SEVERITY_ORDER}


def report_markdown(findings: list[Finding], source: str) -> str:
    """A Markdown triage report."""
    counts = summary_counts(findings)
    lines = [
        f"# Memory triage: {source}",
        "",
        f"{len(findings)} findings: {counts['high']} high, {counts['medium']} medium, {counts['low']} low.",
        "",
        "| Severity | PID | Process | Rule | ATT&CK | Summary |",
        "|---|---|---|---|---|---|",
    ]
    lines += [
        f"| {f.severity} | {f.pid} | {f.process} | {f.rule} | {f.technique} | {f.summary.replace('|', '/')} |"
        for f in findings
    ]
    return "\n".join(lines) + "\n"
