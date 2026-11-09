"""Static checks for the Velociraptor artifacts shipped in artifacts/.

The checks are a mistake-proofing gate: an artifact must be well formed, carry an OS precondition
that matches its name, use every parameter it declares, and call only read-only VQL plugins and
functions (plus ``upload`` for evidence files). CI also loads the same files into a real
Velociraptor binary and runs a collection with them.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from dfir_toolkit._io import InputError, read_bounded

MAX_ARTIFACT_BYTES = 256 * 1024
NAME_RE = re.compile(r"^Custom\.DFIR\.(Generic|Windows|Linux)(\.[A-Z][A-Za-z0-9]*)+$")
PARAM_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
PARAM_TYPES = frozenset({"string", "regex", "bool", "int", "csv"})
BOOL_DEFAULTS = frozenset({"Y", "N"})
REQUIRED_KEYS = ("name", "author", "description", "type", "sources")

# Read-only VQL plugins and functions an evidence-collection artifact may call.
ALLOWED_CALLS = frozenset(
    {
        "array",
        "basename",
        "count",
        "dirname",
        "format",
        "get",
        "glob",
        "hash",
        "if",
        "info",
        "int",
        "lowcase",
        "netstat",
        "now",
        "parse_lines",
        "pslist",
        "read_file",
        "split",
        "stat",
        "timestamp",
        "upload",
        "users",
    }
)
# Calls that change the endpoint or reach the network; named so the error says why.
FORBIDDEN_CALLS = frozenset(
    {
        "copy",
        "execve",
        "http_client",
        "mail",
        "rm",
        "write_csv",
        "write_jsonl",
        "upload_s3",
        "upload_gcs",
        "upload_sftp",
        "upload_webdav",
        "upload_smb",
        "upload_azure",
    }
)
VQL_KEYWORDS = frozenset({"select", "from", "where", "and", "or", "not", "in", "let", "as", "order", "by", "group"})
_STRING_RE = re.compile(r"'''.*?'''|'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", re.S)
_COMMENT_RE = re.compile(r"--[^\n]*|//[^\n]*")
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_OS_PRECONDITION_RE = r"OS\s*=~?\s*['\"]{os}['\"]"


@dataclass(frozen=True)
class Problem:
    """One reason an artifact file is rejected."""

    path: str
    message: str

    def __str__(self) -> str:
        """Render as 'path: message'."""
        return f"{self.path}: {self.message}"


@dataclass(frozen=True)
class Artifact:
    """A validated artifact: its name, target OS, parameters and VQL calls."""

    name: str
    path: str
    os: str
    parameters: tuple[str, ...]
    calls: frozenset[str] = field(default_factory=frozenset)


def strip_vql(query: str) -> str:
    """Remove string literals and comments so only code is scanned."""
    return _COMMENT_RE.sub(" ", _STRING_RE.sub("''", query))


def vql_calls(query: str) -> set[str]:
    """Names of the plugins and functions a VQL query calls."""
    return {m.group(1) for m in _CALL_RE.finditer(strip_vql(query)) if m.group(1).lower() not in VQL_KEYWORDS}


def _check_default(ptype: str, default: Any) -> str | None:
    """Why a parameter default does not fit its type, or None."""
    if default is None:
        return None
    text = str(default)
    if ptype == "bool" and text not in BOOL_DEFAULTS:
        return f"bool default must be Y or N, got {text!r}"
    if ptype == "int" and not re.fullmatch(r"-?\d+", text):
        return f"int default is not an integer: {text!r}"
    if ptype == "regex":
        try:
            re.compile(text)
        except re.error as exc:
            return f"regex default does not compile: {exc}"
    if ptype == "csv":
        rows = list(csv.reader(io.StringIO(text)))
        rows = [r for r in rows if any(cell.strip() for cell in r)]
        if len(rows) < 2:
            return "csv default needs a header row and at least one data row"
    return None


def _check_parameters(raw: Any, code: str, rel: str, out: list[Problem]) -> tuple[str, ...]:
    """Validate the parameters list; every parameter must be used by a query."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        out.append(Problem(rel, "parameters must be a list"))
        return ()
    names: list[str] = []
    for i, param in enumerate(raw):
        if not isinstance(param, dict) or not isinstance(param.get("name"), str):
            out.append(Problem(rel, f"parameter {i} needs a string name"))
            continue
        name = param["name"]
        if not PARAM_NAME_RE.match(name):
            out.append(Problem(rel, f"parameter {name!r} is not an identifier"))
        if name in names:
            out.append(Problem(rel, f"parameter {name!r} declared twice"))
        names.append(name)
        ptype = param.get("type", "string")
        if ptype not in PARAM_TYPES:
            out.append(Problem(rel, f"parameter {name!r} has unknown type {ptype!r}"))
        elif (why := _check_default(ptype, param.get("default"))) is not None:
            out.append(Problem(rel, f"parameter {name!r}: {why}"))
        if not re.search(rf"\b{re.escape(name)}\b", code):
            out.append(Problem(rel, f"parameter {name!r} is never used in a query"))
    return tuple(names)


def check_artifact(path: Path, root: Path | None = None) -> tuple[Artifact | None, list[Problem]]:
    """Validate one artifact file; returns the artifact when it has no problems."""
    rel = path.relative_to(root).as_posix() if root else path.name
    out: list[Problem] = []
    try:
        doc = yaml.safe_load(read_bounded(path, MAX_ARTIFACT_BYTES).decode("utf-8"))
    except (InputError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return None, [Problem(rel, f"not readable YAML: {exc}")]
    if not isinstance(doc, dict):
        return None, [Problem(rel, "top level must be a mapping")]
    out += [Problem(rel, f"missing key {k!r}") for k in REQUIRED_KEYS if not doc.get(k)]
    if out:
        return None, out
    name = doc["name"]
    match = NAME_RE.match(name) if isinstance(name, str) else None
    if match is None:
        return None, [Problem(rel, f"name {name!r} does not match {NAME_RE.pattern}")]
    os_part = match.group(1)
    if doc["type"] != "CLIENT":
        out.append(Problem(rel, f"type must be CLIENT, got {doc['type']!r}"))
    sources = doc["sources"]
    queries: list[str] = []
    if not isinstance(sources, list):
        out.append(Problem(rel, "sources must be a list"))
        sources = []
    for i, src in enumerate(sources):
        query = src.get("query") if isinstance(src, dict) else None
        if not isinstance(query, str) or not re.search(r"\bSELECT\b", query, re.I):
            out.append(Problem(rel, f"source {i} needs a SELECT query"))
        else:
            queries.append(query)
    precondition = doc.get("precondition")
    if os_part != "Generic":
        want = _OS_PRECONDITION_RE.format(os=os_part.lower())
        if not isinstance(precondition, str) or not re.search(want, precondition):
            out.append(Problem(rel, f"{os_part} artifact needs precondition OS = '{os_part.lower()}'"))
    code = "\n".join(strip_vql(q) for q in queries)
    params = _check_parameters(doc.get("parameters"), code, rel, out)
    calls: set[str] = set()
    for query in queries + ([precondition] if isinstance(precondition, str) else []):
        calls |= vql_calls(query)
    for call in sorted(calls):
        if call in FORBIDDEN_CALLS:
            out.append(Problem(rel, f"calls {call}(), which changes the endpoint or the network"))
        elif call not in ALLOWED_CALLS:
            out.append(Problem(rel, f"calls {call}(), which is not on the read-only allowlist"))
    if out:
        return None, out
    return Artifact(name, rel, os_part, params, frozenset(calls)), []


def check_directory(directory: Path) -> tuple[list[Artifact], list[Problem]]:
    """Validate every *.yaml artifact in a directory, including duplicate names."""
    if not directory.is_dir():
        return [], [Problem(str(directory), "not a directory")]
    paths = sorted(directory.glob("*.yaml"))
    if not paths:
        return [], [Problem(str(directory), "no *.yaml artifacts found")]
    artifacts: list[Artifact] = []
    problems: list[Problem] = []
    seen: dict[str, str] = {}
    for path in paths:
        artifact, found = check_artifact(path, directory)
        problems += found
        if artifact is None:
            continue
        if artifact.name in seen:
            problems.append(Problem(artifact.path, f"name {artifact.name} also used by {seen[artifact.name]}"))
            continue
        seen[artifact.name] = artifact.path
        artifacts.append(artifact)
    return artifacts, problems
