"""A seeded, synthetic fleet of ProcessSnapshot hunt results with a few planted rare executables.

Every path and hash is invented; the "planted" entries stand for what an analyst hunts for (an
executable in /dev/shm, a fake sshd in /tmp) and carry no code. Used by the tests and the benchmark.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

ARTIFACT = "Custom.DFIR.Generic.ProcessSnapshot"
BASELINE = (
    "/usr/lib/systemd/systemd",
    "/usr/lib/systemd/systemd-journald",
    "/usr/lib/systemd/systemd-logind",
    "/usr/lib/systemd/systemd-udevd",
    "/usr/lib/systemd/systemd-resolved",
    "/usr/lib/systemd/systemd-timesyncd",
    "/usr/sbin/sshd",
    "/usr/sbin/cron",
    "/usr/sbin/rsyslogd",
    "/usr/bin/dbus-daemon",
    "/usr/sbin/agetty",
    "/usr/bin/bash",
    "/usr/lib/policykit-1/polkitd",
    "/usr/sbin/irqbalance",
    "/usr/lib/accountsservice/accounts-daemon",
    "/usr/bin/python3.12",
    "/usr/sbin/chronyd",
    "/usr/bin/containerd",
    "/usr/sbin/auditd",
    "/usr/lib/snapd/snapd",
)
# Software that only some hosts run, by role: common enough never to be rare.
ROLES = {
    "/usr/sbin/nginx": 0.30,
    "/usr/lib/postgresql/16/bin/postgres": 0.20,
    "/usr/bin/dockerd": 0.25,
    "/usr/sbin/haproxy": 0.10,
}
DRIFT_FRACTION = 0.05  # hosts still on an older sshd build (a different hash)
PLANTED = (
    ("/dev/shm/.cache/kworkerd", 2),
    ("/tmp/.X11-unix/.sshd", 1),
)


@dataclass(frozen=True)
class Fleet:
    """Generated rows plus the planted keys the stack must find."""

    rows: list[dict[str, Any]]
    hosts: int
    planted: frozenset[tuple[str, str]]


def fake_sha256(label: str) -> str:
    """A stable, obviously synthetic SHA-256 for a label."""
    return hashlib.sha256(f"dfir-toolkit-synthetic:{label}".encode()).hexdigest()


def _pick(rng: random.Random, hosts: list[str], count: int) -> list[str]:
    """count distinct hosts chosen at random."""
    return rng.sample(hosts, count)


def generate(hosts: int, seed: int = 0) -> Fleet:
    """Rows for `hosts` hosts; deterministic for a given seed."""
    if hosts < 1:
        raise ValueError("hosts must be at least 1")
    rng = random.Random(seed)
    names = [f"host-{i:05d}.corp.example" for i in range(hosts)]
    per_host: dict[str, list[tuple[str, str]]] = {h: [(p, fake_sha256(p)) for p in BASELINE] for h in names}
    for path, share in ROLES.items():
        for h in _pick(rng, names, max(1, math.ceil(share * hosts))):
            per_host[h].append((path, fake_sha256(path)))
    old_sshd = fake_sha256("/usr/sbin/sshd@old")
    for h in _pick(rng, names, math.ceil(DRIFT_FRACTION * hosts)):
        per_host[h] = [(p, old_sshd if p == "/usr/sbin/sshd" else s) for p, s in per_host[h]]
    planted: set[tuple[str, str]] = set()
    for path, count in PLANTED:
        key = (path, fake_sha256(path))
        planted.add(key)
        for h in _pick(rng, names, min(count, hosts)):
            per_host[h].append(key)
    rows: list[dict[str, Any]] = []
    for idx, h in enumerate(names):
        client = f"C.{idx:016x}"
        for pid, (exe, sha) in enumerate(per_host[h], start=100):
            rows.append(
                {
                    "ClientId": client,
                    "Fqdn": h,
                    "Pid": pid,
                    "Ppid": 1,
                    "Name": exe.rsplit("/", 1)[-1],
                    "Username": "root",
                    "Exe": exe,
                    "CommandLine": exe,
                    "CreateTime": "2026-11-01T00:00:00Z",
                    "ExeSHA256": sha,
                }
            )
        # kernel threads have no executable; the stack must skip them, not count them
        rows.append(
            {"ClientId": client, "Fqdn": h, "Pid": 2, "Ppid": 0, "Name": "kthreadd", "Exe": "", "ExeSHA256": None}
        )
    return Fleet(rows, hosts, frozenset(planted))


def to_jsonl(rows: list[dict[str, Any]]) -> Iterator[str]:
    """Rows as JSON lines, as a Velociraptor hunt export writes them."""
    for row in rows:
        yield json.dumps(row, sort_keys=True) + "\n"
