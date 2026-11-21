"""Reading hunt and collection results, and least-frequency stacking across a fleet."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from dfir_toolkit import hunt, synth
from dfir_toolkit._io import InputError

PROC = "Custom.DFIR.Generic.ProcessSnapshot"


def jsonl(tmp_path: Path, rows: list[Any], name: str = "hunt.jsonl") -> Path:
    """Write rows as JSON lines."""
    path = tmp_path / name
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def row(host: str, exe: str, sha: str = "aa") -> hunt.Row:
    """A process row for a host."""
    return hunt.Row(host, PROC, {"Exe": exe, "ExeSHA256": sha})


def test_jsonl_hosts_come_from_fqdn_then_client_id_then_default(tmp_path: Path) -> None:
    path = jsonl(
        tmp_path,
        [{"Fqdn": "a.example", "ClientId": "C.0000000000000001"}, {"ClientId": "C.00000000000000ff"}, {"Exe": "x"}],
    )
    rows = list(hunt.read_jsonl(path, PROC, host="fallback"))
    assert [r.host for r in rows] == ["a.example", "C.00000000000000ff", "fallback"]
    assert all(r.artifact == PROC for r in rows)


def test_blank_lines_are_skipped_and_an_empty_file_gives_no_rows(tmp_path: Path) -> None:
    path = tmp_path / "e.jsonl"
    path.write_text("\n\n", encoding="utf-8")
    assert list(hunt.read_jsonl(path, PROC, "h")) == []
    report = hunt.stack(iter([]), PROC)
    assert (report.hosts, report.rows, report.rare) == (0, 0, ())


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('{"Exe": "x"}\n', "no Fqdn or ClientId"),
        ('{"ClientId": "C.123"}\n', "is not a Velociraptor client id"),
        ('{"ClientId": 5}\n', "is not a Velociraptor client id"),
        ('{"Fqdn": "a"}\nnot json\n', ":2: not JSON"),
        ('["a", "list"]\n', "expected a JSON object"),
    ],
)
def test_bad_jsonl_fails_with_the_line_number(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(InputError, match=message):
        list(hunt.read_jsonl(path, PROC))


def test_overlong_line_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hunt, "MAX_LINE_BYTES", 64)
    path = jsonl(tmp_path, [{"Fqdn": "a", "Exe": "x" * 100}])
    with pytest.raises(InputError, match="line longer than 64 bytes"):
        list(hunt.read_jsonl(path, PROC))


def test_missing_file_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="cannot read"):
        list(hunt.read_jsonl(tmp_path / "nope.jsonl", PROC))


def make_zip(tmp_path: Path, members: dict[str, str], name: str = "host-a.zip") -> Path:
    """A collection zip with the given members."""
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for member, text in members.items():
            zf.writestr(member, text)
    return path


def test_collection_zip_results_are_read_without_extracting(tmp_path: Path) -> None:
    path = make_zip(
        tmp_path,
        {
            "client_info.json": json.dumps({"Hostname": "ws-17", "Fqdn": "ws-17.corp.example"}),
            f"results/{PROC}.json": '{"Exe": "/usr/bin/a", "ExeSHA256": "11"}\n{"Exe": "/usr/bin/b", "ExeSHA256": "22"}\n',
            "results/Custom.DFIR.Linux.Persistence%2FFiles.json": '{"OSPath": "/etc/crontab", "SHA256": "33"}\n',
            "uploads/auto/etc/passwd": "not read",
            "log.json": "{}\n",
        },
    )
    rows = list(hunt.read_collection_zip(path))
    assert {(r.host, r.artifact) for r in rows} == {
        ("ws-17.corp.example", PROC),
        ("ws-17.corp.example", "Custom.DFIR.Linux.Persistence"),
    }
    assert len(rows) == 3
    assert not (tmp_path / "results").exists()


def test_zip_host_falls_back_to_file_name_and_explicit_host_wins(tmp_path: Path) -> None:
    path = make_zip(tmp_path, {f"results/{PROC}.json": '{"Exe": "a", "ExeSHA256": "1"}\n'}, "srv-9.zip")
    assert next(iter(hunt.read_collection_zip(path))).host == "srv-9"
    assert next(iter(hunt.read_collection_zip(path, host="given"))).host == "given"


def test_zip_member_over_the_size_limit_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = make_zip(tmp_path, {f"results/{PROC}.json": '{"Exe": "a"}\n' * 1000})
    monkeypatch.setattr(hunt, "MAX_MEMBER_BYTES", 1000)
    with pytest.raises(InputError, match="over 1000 bytes"):
        list(hunt.read_collection_zip(path, "h"))


def test_decompression_is_bounded_even_if_the_header_lies(tmp_path: Path) -> None:
    limited = hunt._Limited(__import__("io").BytesIO(b"x" * 100), 10, "member")
    buf = bytearray(64)
    with pytest.raises(InputError, match="past the size limit"):
        limited.readinto(buf)


@pytest.mark.parametrize(
    ("members", "message"),
    [
        ({"client_info.json": "{not json"}, "client_info.json is not JSON"),
    ],
)
def test_bad_client_info_is_rejected(tmp_path: Path, members: dict[str, str], message: str) -> None:
    with pytest.raises(InputError, match=message):
        list(hunt.read_collection_zip(make_zip(tmp_path, members)))


def test_non_utf8_client_info_is_an_input_error(tmp_path: Path) -> None:
    path = tmp_path / "host.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("client_info.json", b'{"Fqdn": "\xff"}')
    with pytest.raises(InputError, match=r"client_info.json is not JSON"):
        list(hunt.read_collection_zip(path))


def test_a_non_zip_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "fake.zip"
    path.write_bytes(b"PK not really")
    with pytest.raises(InputError, match="not a readable zip"):
        list(hunt.read_collection_zip(path))


def test_read_results_needs_an_artifact_for_jsonl(tmp_path: Path) -> None:
    path = jsonl(tmp_path, [{"Fqdn": "a"}])
    with pytest.raises(InputError, match="needs --artifact"):
        list(hunt.read_results([path], None))


@pytest.mark.parametrize(
    ("hosts", "fraction", "want"), [(1, 0.01, 1), (99, 0.01, 1), (200, 0.01, 2), (1000, 0.01, 10), (1000, 0.005, 5)]
)
def test_rare_threshold(hosts: int, fraction: float, want: int) -> None:
    assert hunt.rare_threshold(hosts, fraction) == want


@pytest.mark.parametrize("fraction", [0.0, 1.0, -0.1, 2.0])
def test_rare_threshold_rejects_bad_fractions(fraction: float) -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        hunt.rare_threshold(10, fraction)


def test_stack_counts_distinct_hosts_not_rows() -> None:
    rows = [row(f"h{i}", "/usr/bin/common") for i in range(100)]
    rows += [row("h1", "/usr/bin/rare"), row("h1", "/usr/bin/rare"), row("h1", "/usr/bin/rare")]
    report = hunt.stack(iter(rows), PROC)
    assert report.hosts == 100
    assert report.rows == 103
    assert report.max_hosts == 1
    assert [(e.key, e.hosts) for e in report.rare] == [(("/usr/bin/rare", "aa"), ("h1",))]


def test_rows_without_a_key_are_skipped_not_counted() -> None:
    rows = [row(f"h{i}", "/usr/bin/a") for i in range(200)]
    rows += [
        hunt.Row("h1", PROC, {"Exe": "", "ExeSHA256": None}),
        hunt.Row("h2", PROC, {"Exe": "/x", "ExeSHA256": None}),
    ]
    report = hunt.stack(iter(rows), PROC)
    assert report.skipped_rows == 2
    assert report.rare == ()


def test_the_same_path_with_another_hash_is_a_different_key() -> None:
    rows = [row(f"h{i}", "/usr/sbin/sshd", "good") for i in range(300)] + [row("h7", "/usr/sbin/sshd", "evil")]
    report = hunt.stack(iter(rows), PROC)
    assert [e.key for e in report.rare] == [("/usr/sbin/sshd", "evil")]


def test_suspicious_paths_sort_first_among_equal_counts() -> None:
    rows = [row(f"h{i}", "/usr/bin/a") for i in range(100)]
    rows += [row("h1", "/opt/tool/x"), row("h2", "/dev/shm/.x/y"), row("h3", r"C:\Users\Public\a.exe")]
    report = hunt.stack(iter(rows), PROC)
    assert [(e.key[0], e.suspicious_path) for e in report.rare] == [
        ("/dev/shm/.x/y", True),
        (r"C:\Users\Public\a.exe", True),
        ("/opt/tool/x", False),
    ]


def test_rows_of_other_artifacts_are_ignored() -> None:
    rows = [hunt.Row("h1", "Custom.DFIR.Linux.Persistence", {"OSPath": "/x", "SHA256": "1"}), row("h1", "/a")]
    assert hunt.stack(iter(rows), PROC).rows == 1


def test_unknown_artifact_is_rejected() -> None:
    with pytest.raises(ValueError, match="no stack key"):
        hunt.stack(iter([]), "Custom.DFIR.Nope")


@pytest.mark.parametrize("seed", range(5))
def test_planted_executables_are_exactly_the_rare_set(seed: int) -> None:
    fleet = synth.generate(300, seed)
    rows = (hunt.Row(r["Fqdn"], PROC, r) for r in fleet.rows)
    report = hunt.stack(rows, PROC, 0.01)
    assert report.hosts == 300
    assert {e.key for e in report.rare} == set(fleet.planted)
    assert all(e.suspicious_path for e in report.rare)
    assert report.skipped_rows == 300


def test_synth_is_deterministic_and_validates() -> None:
    assert synth.generate(50, 3).rows == synth.generate(50, 3).rows
    assert synth.generate(50, 3).rows != synth.generate(50, 4).rows
    with pytest.raises(ValueError, match="at least 1"):
        synth.generate(0)


def test_markdown_report_escapes_pipes() -> None:
    rows = [row(f"h{i}", "/a") for i in range(100)] + [row("h1", "/b|c")]
    text = hunt.report_markdown(hunt.stack(iter(rows), PROC))
    assert "| 1 | /b\\|c | aa | no | h1 |" in text
    assert "100 hosts, 101 rows" in text


def test_report_json_round_trips() -> None:
    rows = [row(f"h{i}", "/a") for i in range(100)] + [row("h1", "/dev/shm/b")]
    data = json.loads(json.dumps(hunt.stack(iter(rows), PROC).to_json()))
    assert data["rare"] == [
        {"key": {"Exe": "/dev/shm/b", "ExeSHA256": "aa"}, "host_count": 1, "hosts": ["h1"], "suspicious_path": True}
    ]
