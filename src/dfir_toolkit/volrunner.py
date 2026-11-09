"""Run Volatility 3 plugins on a memory image and keep their JSON output.

Volatility 3 is an optional dependency (``pip install -e ".[vol]"``) and runs in a child process
with a timeout, so a hung or crashing plugin cannot take the toolkit down with it. Output goes to a
temporary file first and is renamed into place only after it parses.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from dfir_toolkit._io import InputError, read_bounded
from dfir_toolkit.memory import MAX_PLUGIN_OUTPUT_BYTES, parse_vol_json

VOL_PLUGINS: dict[str, str] = {
    "pslist": "windows.pslist.PsList",
    "psscan": "windows.psscan.PsScan",
    "malfind": "windows.malware.malfind.Malfind",
    "netscan": "windows.netscan.NetScan",
    "cmdline": "windows.cmdline.CmdLine",
}
# `python -c` leaves "-c" in sys.argv[0]; Volatility parses argv, so name it first.
DEFAULT_VOL = (sys.executable, "-c", 'import sys; sys.argv[0] = "vol"; from volatility3.cli import main; main()')
STDERR_TAIL = 2000


class VolatilityError(RuntimeError):
    """Volatility exited with an error, timed out or printed unusable output."""


@dataclass(frozen=True)
class PluginRun:
    """Where one plugin's output went and how long it took."""

    plugin: str
    output: Path
    rows: int
    seconds: float


def vol_command(
    plugin: str,
    image: Path | None,
    cache_dir: Path,
    offline: bool,
    vol: tuple[str, ...] = DEFAULT_VOL,
) -> list[str]:
    """The argument list for one Volatility run with the JSON renderer."""
    cmd = [*vol, "-q", "-r", "json", "--cache-path", str(cache_dir)]
    if offline:
        cmd.append("--offline")
    if image is not None:
        cmd += ["-f", str(image)]
    return [*cmd, plugin]


def run_raw(
    cmd: list[str],
    out_path: Path,
    timeout_s: float,
) -> float:
    """Run a command with stdout to out_path; raise on timeout or non-zero exit. Returns seconds."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        with out_path.open("wb") as out:
            proc = subprocess.run(  # noqa: S603 - argument list, no shell
                cmd, stdout=out, stderr=subprocess.PIPE, timeout=timeout_s, check=False
            )
    except subprocess.TimeoutExpired as exc:
        out_path.unlink(missing_ok=True)
        raise VolatilityError(f"{cmd[-1]} timed out after {timeout_s:.0f} s") from exc
    except OSError as exc:
        out_path.unlink(missing_ok=True)
        raise VolatilityError(f"cannot start Volatility: {exc}") from exc
    elapsed = time.monotonic() - started
    if proc.returncode != 0:
        out_path.unlink(missing_ok=True)
        tail = proc.stderr.decode("utf-8", "replace")[-STDERR_TAIL:].strip()
        raise VolatilityError(f"{cmd[-1]} exited with {proc.returncode}: {tail}")
    return elapsed


def run_plugins(
    image: Path,
    outdir: Path,
    plugins: tuple[str, ...] = tuple(VOL_PLUGINS),
    timeout_s: float = 1800.0,
    offline: bool = False,
    vol: tuple[str, ...] = DEFAULT_VOL,
) -> list[PluginRun]:
    """Run each plugin on an image; each <plugin>.json appears only once it parses."""
    if not image.is_file():
        raise InputError(f"{image}: memory image not found")
    unknown = [p for p in plugins if p not in VOL_PLUGINS]
    if unknown:
        raise InputError(f"unknown plugins {unknown}; known: {', '.join(VOL_PLUGINS)}")
    if timeout_s <= 0:
        raise InputError("timeout must be positive")
    cache = outdir / ".volcache"
    cache.mkdir(parents=True, exist_ok=True)
    runs: list[PluginRun] = []
    for plugin in plugins:
        final = outdir / f"{plugin}.json"
        partial = outdir / f".{plugin}.json.partial"
        seconds = run_raw(vol_command(VOL_PLUGINS[plugin], image, cache, offline, vol), partial, timeout_s)
        try:
            text = read_bounded(partial, MAX_PLUGIN_OUTPUT_BYTES).decode("utf-8", "replace")
            rows = parse_vol_json(text, plugin, str(partial))
        except InputError:
            partial.unlink(missing_ok=True)
            raise
        os.replace(partial, final)
        runs.append(PluginRun(plugin, final, len(rows), seconds))
    return runs
