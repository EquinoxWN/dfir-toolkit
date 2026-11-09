"""Bounded reads and atomic writes shared by every module."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


class InputError(ValueError):
    """Raised when an input file is missing, too large or malformed."""


def read_bounded(path: Path, max_bytes: int) -> bytes:
    """Read a whole file, refusing files larger than max_bytes."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputError(f"{path}: cannot read ({exc.strerror or exc})") from exc
    if size > max_bytes:
        raise InputError(f"{path}: {size} bytes is over the {max_bytes}-byte limit")
    with path.open("rb") as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise InputError(f"{path}: grew past the {max_bytes}-byte limit while reading")
    return data


def atomic_write_text(path: Path, text: str) -> None:
    """Write text to a sibling temp file, fsync it, then rename over the target."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
