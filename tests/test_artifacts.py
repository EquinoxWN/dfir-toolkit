"""Static checks of the Velociraptor artifacts: the shipped set passes, each defect is caught."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dfir_toolkit import artifacts

ROOT = Path(__file__).resolve().parents[1]

GOOD = """\
name: Custom.DFIR.Linux.Test.Example
author: tester
description: example
type: CLIENT
precondition: SELECT OS FROM info() WHERE OS = 'linux'
parameters:
  - name: PathGlob
    type: string
    default: /etc/*
sources:
  - query: |
      SELECT OSPath, hash(path=OSPath).SHA256 AS SHA256 FROM glob(globs=PathGlob)
"""


def write(tmp_path: Path, text: str, name: str = "a.yaml") -> Path:
    """Write one artifact file."""
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def problems_for(tmp_path: Path, text: str) -> list[str]:
    """Problem messages for one artifact text."""
    artifact, found = artifacts.check_artifact(write(tmp_path, text))
    assert (artifact is None) == bool(found)
    return [p.message for p in found]


def test_every_shipped_artifact_passes() -> None:
    found, problems = artifacts.check_directory(ROOT / "artifacts")
    assert problems == []
    assert {a.name for a in found} == {
        "Custom.DFIR.Generic.ProcessSnapshot",
        "Custom.DFIR.Generic.NetworkConnections",
        "Custom.DFIR.Linux.Persistence",
        "Custom.DFIR.Linux.Collect.Logs",
        "Custom.DFIR.Windows.Persistence.RunKeys",
    }
    for a in found:
        assert a.path == f"{a.name}.yaml"
        assert not a.calls & artifacts.FORBIDDEN_CALLS


def test_shipped_artifacts_have_stack_keys() -> None:
    from dfir_toolkit.hunt import STACK_KEYS

    found, _ = artifacts.check_directory(ROOT / "artifacts")
    assert {a.name for a in found} == set(STACK_KEYS)


def test_a_good_artifact_passes(tmp_path: Path) -> None:
    artifact, found = artifacts.check_artifact(write(tmp_path, GOOD))
    assert found == []
    assert artifact is not None
    assert artifact.os == "Linux"
    assert artifact.parameters == ("PathGlob",)
    assert artifact.calls == frozenset({"glob", "hash", "info"})


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("author: tester\n", "", "missing key 'author'"),
        ("name: Custom.DFIR.Linux.Test.Example", "name: Linux.Test.Example", "does not match"),
        ("name: Custom.DFIR.Linux.Test.Example", "name: Custom.DFIR.Linux.test", "does not match"),
        ("type: CLIENT", "type: SERVER", "type must be CLIENT"),
        ("precondition: SELECT OS FROM info() WHERE OS = 'linux'\n", "", "needs precondition OS = 'linux'"),
        ("OS = 'linux'", "OS = 'windows'", "needs precondition OS = 'linux'"),
        ("glob(globs=PathGlob)", "glob(globs='/etc/*')", "'PathGlob' is never used"),
        ("type: string", "type: path", "unknown type 'path'"),
        ("hash(path=OSPath).SHA256", "execve(argv=['id'])", "calls execve(), which changes the endpoint"),
        ("hash(path=OSPath).SHA256", "http_client(url='https://example.invalid')", "calls http_client()"),
        ("hash(path=OSPath).SHA256", "rm(filename=OSPath)", "calls rm()"),
        ("hash(path=OSPath).SHA256", "parse_evtx(filename=OSPath)", "not on the read-only allowlist"),
        ("      SELECT OSPath", "      LET x = 1", "needs a SELECT query"),
    ],
)
def test_each_defect_is_reported(tmp_path: Path, old: str, new: str, message: str) -> None:
    assert old in GOOD
    found = problems_for(tmp_path, GOOD.replace(old, new))
    assert any(message in m for m in found), found


@pytest.mark.parametrize(
    ("ptype", "default", "message"),
    [
        ("bool", "yes", "bool default must be Y or N"),
        ("int", "ten", "int default is not an integer"),
        ("regex", "([a-z", "regex default does not compile"),
        ("csv", "Glob\n", "csv default needs a header row"),
    ],
)
def test_parameter_defaults_must_fit_their_type(tmp_path: Path, ptype: str, default: str, message: str) -> None:
    text = GOOD.replace("type: string\n    default: /etc/*", f"type: {ptype}\n    default: {json.dumps(default)}")
    assert any(message in m for m in problems_for(tmp_path, text))


@pytest.mark.parametrize(
    ("ptype", "default"), [("bool", "Y"), ("int", "42"), ("regex", "^a.c$"), ("csv", "Glob\n/etc/*\n")]
)
def test_valid_defaults_pass(tmp_path: Path, ptype: str, default: str) -> None:
    text = GOOD.replace("type: string\n    default: /etc/*", f"type: {ptype}\n    default: {json.dumps(default)}")
    assert problems_for(tmp_path, text) == []


def test_calls_inside_strings_and_comments_are_ignored(tmp_path: Path) -> None:
    text = GOOD.replace(
        "SELECT OSPath,",
        "-- execve(argv=1) is never called here\n      SELECT OSPath, 'rm(x)' AS Note, \"http_client()\" AS N2,",
    )
    assert problems_for(tmp_path, text) == []


def test_parameters_must_be_unique_identifiers(tmp_path: Path) -> None:
    dup = GOOD.replace("sources:", "  - name: PathGlob\n    default: x\nsources:")
    assert any("declared twice" in m for m in problems_for(tmp_path, dup))
    bad = GOOD.replace("name: PathGlob", "name: 1bad").replace("globs=PathGlob", "globs=1bad")
    assert any("not an identifier" in m for m in problems_for(tmp_path, bad))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("name: [unclosed", "not readable YAML"),
        ("- just\n- a list\n", "top level must be a mapping"),
        (GOOD.replace("sources:\n", "sources: 7\nignored:\n"), "sources must be a list"),
        (GOOD.replace("parameters:\n", "parameters: 3\nignored:\n"), "parameters must be a list"),
    ],
)
def test_malformed_files_are_rejected(tmp_path: Path, text: str, message: str) -> None:
    assert any(message in m for m in problems_for(tmp_path, text))


def test_oversized_file_is_rejected(tmp_path: Path) -> None:
    text = GOOD + "#" * (artifacts.MAX_ARTIFACT_BYTES + 1)
    assert any("limit" in m for m in problems_for(tmp_path, text))


def test_directory_checks(tmp_path: Path) -> None:
    assert artifacts.check_directory(tmp_path / "missing")[1][0].message == "not a directory"
    assert "no *.yaml" in artifacts.check_directory(tmp_path)[1][0].message
    write(tmp_path, GOOD, "one.yaml")
    write(tmp_path, GOOD, "two.yaml")
    found, problems = artifacts.check_directory(tmp_path)
    assert len(found) == 1
    assert [str(p) for p in problems] == ["two.yaml: name Custom.DFIR.Linux.Test.Example also used by one.yaml"]


def test_vql_calls_extracts_names_and_skips_keywords() -> None:
    query = "SELECT * FROM foreach(row={SELECT x FROM glob(globs='a(b)')}, query={SELECT * FROM stat(filename=x)}) WHERE NOT (x IN (1,2))"
    assert artifacts.vql_calls(query) == {"foreach", "glob", "stat"}
