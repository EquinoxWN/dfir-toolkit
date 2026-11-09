"""Bounded reads and atomic writes."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from dfir_toolkit import _io


def test_atomic_write_replaces_and_leaves_no_temp(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "r.json"
    _io.atomic_write_text(target, "one")
    _io.atomic_write_text(target, "two")
    assert target.read_text(encoding="utf-8") == "two"
    assert [p.name for p in target.parent.iterdir()] == ["r.json"]


def test_failed_write_keeps_the_old_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "r.json"
    _io.atomic_write_text(target, "old")

    def boom(src: str, dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        _io.atomic_write_text(target, "new")
    assert target.read_text(encoding="utf-8") == "old"
    assert [p.name for p in tmp_path.iterdir()] == ["r.json"]


def test_read_bounded(tmp_path: Path) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"12345")
    assert _io.read_bounded(path, 5) == b"12345"
    with pytest.raises(_io.InputError, match="over the 4-byte limit"):
        _io.read_bounded(path, 4)
    with pytest.raises(_io.InputError, match="cannot read"):
        _io.read_bounded(tmp_path / "missing", 4)
