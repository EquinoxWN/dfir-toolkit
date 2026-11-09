"""Read Velociraptor hunt and collection results and stack them across hosts.

Stacking (least frequency of occurrence) counts, for each value of a key such as an executable
path and hash, how many distinct hosts report it. Software every host runs is common; what only one
or two hosts run is where an analyst looks first.
"""

from __future__ import annotations

import io
import json
import math
import re
import zipfile
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import unquote

from dfir_toolkit._io import InputError

MAX_LINE_BYTES = 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_ROWS = 50_000_000
CLIENT_ID_RE = re.compile(r"^C\.[0-9a-f]{16}$")
EMPTY_VALUES = frozenset({"", "0.0.0.0", "::", "N/A"})  # noqa: S104 - compared, never bound

# Which columns identify "the same thing" on two hosts, per artifact.
STACK_KEYS: dict[str, tuple[str, ...]] = {
    "Custom.DFIR.Generic.ProcessSnapshot": ("Exe", "ExeSHA256"),
    "Custom.DFIR.Generic.NetworkConnections": ("RemoteAddr", "RemotePort"),
    "Custom.DFIR.Linux.Persistence": ("OSPath", "SHA256"),
    "Custom.DFIR.Windows.Persistence.RunKeys": ("ValueName", "Command"),
    "Custom.DFIR.Linux.Collect.Logs": ("OSPath",),
}
# Executables in these places are flagged whatever their frequency.
SUSPICIOUS_PATH_RE = re.compile(
    r"^(/tmp/|/var/tmp/|/dev/shm/)|\\(appdata\\local\\temp|users\\public|windows\\temp|\$recycle\.bin)\\",
    re.I,
)


class _Readline(Protocol):
    """Anything with a bounded binary readline."""

    def readline(self, size: int = -1, /) -> bytes:
        """Read one line of at most size bytes."""
        ...


@dataclass(frozen=True)
class Row:
    """One result row with the host that produced it."""

    host: str
    artifact: str
    values: dict[str, Any]


@dataclass(frozen=True)
class StackEntry:
    """A key value and the hosts that reported it."""

    key: tuple[str, ...]
    hosts: tuple[str, ...]
    suspicious_path: bool

    @property
    def count(self) -> int:
        """Number of distinct hosts."""
        return len(self.hosts)


@dataclass(frozen=True)
class StackReport:
    """The result of stacking one artifact across a fleet."""

    artifact: str
    key_columns: tuple[str, ...]
    hosts: int
    rows: int
    skipped_rows: int
    distinct_keys: int
    max_hosts: int
    rare: tuple[StackEntry, ...]

    def to_json(self) -> dict[str, Any]:
        """A JSON-ready dict, rare entries first by host count."""
        return {
            "artifact": self.artifact,
            "key_columns": list(self.key_columns),
            "hosts": self.hosts,
            "rows": self.rows,
            "skipped_rows": self.skipped_rows,
            "distinct_keys": self.distinct_keys,
            "rare_threshold_hosts": self.max_hosts,
            "rare": [
                {
                    "key": dict(zip(self.key_columns, e.key, strict=True)),
                    "host_count": e.count,
                    "hosts": list(e.hosts),
                    "suspicious_path": e.suspicious_path,
                }
                for e in self.rare
            ],
        }


def _host_of(values: dict[str, Any], default: str | None, where: str) -> str:
    """The host a row belongs to: Fqdn, then ClientId, then the default."""
    fqdn = values.get("Fqdn")
    if isinstance(fqdn, str) and fqdn:
        return fqdn
    client = values.get("ClientId")
    if client is not None:
        if not isinstance(client, str) or not CLIENT_ID_RE.match(client):
            raise InputError(f"{where}: ClientId {client!r} is not a Velociraptor client id")
        return client
    if default:
        return default
    raise InputError(f"{where}: row has no Fqdn or ClientId and no --host was given")


def _iter_lines(stream: _Readline, where: str) -> Iterator[tuple[int, dict[str, Any]]]:
    """Parse a JSON-lines byte stream, bounding each line."""
    for lineno, raw in enumerate(iter(lambda: stream.readline(MAX_LINE_BYTES + 1), b""), start=1):
        if len(raw) > MAX_LINE_BYTES:
            raise InputError(f"{where}:{lineno}: line longer than {MAX_LINE_BYTES} bytes")
        text = raw.strip()
        if not text:
            continue
        try:
            obj = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise InputError(f"{where}:{lineno}: not JSON ({exc})") from exc
        if not isinstance(obj, dict):
            raise InputError(f"{where}:{lineno}: expected a JSON object per line")
        yield lineno, obj


def read_jsonl(path: Path, artifact: str, host: str | None = None) -> Iterator[Row]:
    """Rows from a hunt export (JSON lines with Fqdn or ClientId columns)."""
    try:
        fh = path.open("rb")
    except OSError as exc:
        raise InputError(f"{path}: cannot read ({exc.strerror or exc})") from exc
    with fh:
        for lineno, obj in _iter_lines(fh, str(path)):
            yield Row(_host_of(obj, host, f"{path}:{lineno}"), artifact, obj)


def _artifact_of_member(name: str) -> str | None:
    """Artifact name of a results/ member of a collection zip, or None."""
    if not name.startswith("results/") or not name.endswith(".json"):
        return None
    stem = unquote(name[len("results/") : -len(".json")]).split("/", 1)[0]
    return stem or None


def _zip_host(zf: zipfile.ZipFile, path: Path) -> str:
    """Host named in client_info.json, else the zip's file name."""
    try:
        info = zf.getinfo("client_info.json")
    except KeyError:
        return path.stem
    if info.file_size > MAX_LINE_BYTES:
        raise InputError(f"{path}: client_info.json is too large")
    try:
        data = json.loads(zf.read(info))
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: client_info.json is not JSON ({exc})") from exc
    for key in ("Fqdn", "Hostname", "ClientId"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, str) and value:
            return value
    return path.stem


def read_collection_zip(path: Path, host: str | None = None) -> Iterator[Row]:
    """Rows from a Velociraptor collection zip (results/<Artifact>.json members), never extracted."""
    try:
        zf = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise InputError(f"{path}: not a readable zip ({exc})") from exc
    with zf:
        zip_host = host or _zip_host(zf, path)
        for info in zf.infolist():
            artifact = _artifact_of_member(info.filename)
            if artifact is None:
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                raise InputError(f"{path}: {info.filename} is over {MAX_MEMBER_BYTES} bytes")
            with zf.open(info) as member:
                bounded = io.BufferedReader(_Limited(member, MAX_MEMBER_BYTES, f"{path}!{info.filename}"))
                for lineno, obj in _iter_lines(bounded, f"{path}!{info.filename}"):
                    where = f"{path}!{info.filename}:{lineno}"
                    yield Row(_host_of(obj, zip_host, where), artifact, obj)


class _Limited(io.RawIOBase):
    """A raw stream that fails once more than `limit` bytes were read (zip bomb guard)."""

    def __init__(self, inner: Any, limit: int, where: str) -> None:
        """Wrap inner, allowing at most limit bytes."""
        self._inner = inner
        self._left = limit
        self._where = where

    def readable(self) -> bool:
        """Always readable."""
        return True

    def readinto(self, buffer: Any) -> int:
        """Read into buffer, failing past the limit."""
        data = self._inner.read(len(buffer))
        self._left -= len(data)
        if self._left < 0:
            raise InputError(f"{self._where}: decompressed past the size limit")
        buffer[: len(data)] = data
        return len(data)


def read_results(paths: Iterable[Path], artifact: str | None, host: str | None = None) -> Iterator[Row]:
    """Rows from a mix of collection zips and JSON-lines hunt exports."""
    for path in paths:
        if path.suffix.lower() == ".zip":
            yield from read_collection_zip(path, host)
        else:
            if artifact is None:
                raise InputError(f"{path}: JSON-lines input needs --artifact")
            yield from read_jsonl(path, artifact, host)


def rare_threshold(hosts: int, fraction: float) -> int:
    """Largest host count still called rare: at least 1, else floor(fraction * hosts)."""
    if not 0 < fraction < 1:
        raise ValueError(f"fraction must be between 0 and 1, got {fraction}")
    return max(1, math.floor(fraction * hosts))


def stack(rows: Iterable[Row], artifact: str, fraction: float = 0.01) -> StackReport:
    """Count hosts per key value for one artifact and keep the rare ones."""
    keys = STACK_KEYS.get(artifact)
    if keys is None:
        raise ValueError(f"no stack key defined for {artifact}; known: {', '.join(sorted(STACK_KEYS))}")
    hosts_by_key: dict[tuple[str, ...], set[str]] = defaultdict(set)
    all_hosts: set[str] = set()
    n_rows = skipped = 0
    for row in rows:
        if row.artifact != artifact:
            continue
        if n_rows >= MAX_ROWS:
            raise InputError(f"more than {MAX_ROWS} rows for {artifact}")
        n_rows += 1
        all_hosts.add(row.host)
        key = tuple("" if row.values.get(k) is None else str(row.values.get(k)) for k in keys)
        if any(v in EMPTY_VALUES for v in key):
            skipped += 1
            continue
        hosts_by_key[key].add(row.host)
    limit = rare_threshold(len(all_hosts), fraction) if all_hosts else 0
    rare = sorted(
        (
            StackEntry(k, tuple(sorted(h)), bool(SUSPICIOUS_PATH_RE.search(k[0])))
            for k, h in hosts_by_key.items()
            if len(h) <= limit
        ),
        key=lambda e: (e.count, not e.suspicious_path, e.key),
    )
    return StackReport(artifact, keys, len(all_hosts), n_rows, skipped, len(hosts_by_key), limit, tuple(rare))


def report_markdown(report: StackReport) -> str:
    """A short Markdown table of the rare entries."""
    lines = [
        f"# Stack: {report.artifact}",
        "",
        f"{report.hosts} hosts, {report.rows} rows ({report.skipped_rows} without a key), "
        f"{report.distinct_keys} distinct keys; rare means on at most {report.max_hosts} host(s).",
        "",
        "| Hosts | " + " | ".join(report.key_columns) + " | Suspicious path | Seen on |",
        "|---|" + "---|" * len(report.key_columns) + "---|---|",
    ]
    for e in report.rare:
        cells = " | ".join(v.replace("|", "\\|") for v in e.key)
        seen = ", ".join(e.hosts[:5]) + (" ..." if e.count > 5 else "")
        lines.append(f"| {e.count} | {cells} | {'yes' if e.suspicious_path else 'no'} | {seen} |")
    return "\n".join(lines) + "\n"
