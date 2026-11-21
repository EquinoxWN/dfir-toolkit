"""The dfir command line, end to end."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from dfir_toolkit import cli

ROOT = Path(__file__).resolve().parents[1]
INJECTED = ROOT / "tests" / "fixtures" / "memory" / "injected"


def test_artifacts_check_passes_on_the_shipped_set(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["artifacts", "check", str(ROOT / "artifacts")]) == 0
    assert "5 artifacts valid, 0 problems" in capsys.readouterr().out


def test_artifacts_check_fails_on_a_bad_artifact(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "bad.yaml").write_text("name: x\n", encoding="utf-8")
    assert cli.main(["artifacts", "check", str(tmp_path)]) == 1
    assert "FAIL bad.yaml" in capsys.readouterr().err


def test_synth_then_stack_finds_the_planted_executables(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    export = tmp_path / "hunt.jsonl"
    assert cli.main(["hunt", "synth", "--hosts", "300", "--seed", "1", "--out", str(export)]) == 0
    out_json, out_md = tmp_path / "r.json", tmp_path / "r.md"
    code = cli.main(
        [
            "hunt",
            "stack",
            str(export),
            "--artifact",
            "Custom.DFIR.Generic.ProcessSnapshot",
            "--json",
            str(out_json),
            "--md",
            str(out_md),
        ]
    )
    assert code == 0
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["hosts"] == 300
    assert sorted(r["key"]["Exe"] for r in report["rare"]) == ["/dev/shm/.cache/kworkerd", "/tmp/.X11-unix/.sshd"]
    assert "# Stack: Custom.DFIR.Generic.ProcessSnapshot" in out_md.read_text(encoding="utf-8")
    assert "2 rare (<= 3 hosts)" in capsys.readouterr().out


def test_stack_infers_the_artifact_from_a_single_artifact_zip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import zipfile

    path = tmp_path / "h.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("results/Custom.DFIR.Linux.Persistence.json", '{"OSPath": "/etc/cron.d/x", "SHA256": "ab"}\n')
    assert cli.main(["hunt", "stack", str(path)]) == 0
    assert "Custom.DFIR.Linux.Persistence: 1 hosts" in capsys.readouterr().out


def test_stack_reports_input_errors_with_exit_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{oops\n", encoding="utf-8")
    assert cli.main(["hunt", "stack", str(bad), "--artifact", "Custom.DFIR.Generic.ProcessSnapshot"]) == 1
    assert "not JSON" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["hunt", "stack", "x.jsonl", "--rare-fraction", "1.5"],
        ["hunt", "stack", "x.jsonl", "--rare-fraction", "abc"],
        ["hunt", "synth", "--hosts", "0", "--out", "x"],
        ["hunt", "synth", "--hosts", "many", "--out", "x"],
        ["memory", "run", "--image", "a", "--outdir", "b", "--timeout", "0"],
        ["memory", "run", "--image", "a", "--outdir", "b", "--timeout", "soon"],
        ["hunt", "stack", "x.jsonl", "--artifact", "Nope"],
        ["hunt", "stack", "x.jsonl", "--show", "-1"],
    ],
)
def test_invalid_arguments_exit_2(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2


def test_memory_triage_writes_reports_and_can_fail_the_build(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_json, out_md = tmp_path / "f.json", tmp_path / "f.md"
    assert cli.main(["memory", "triage", str(INJECTED), "--json", str(out_json), "--md", str(out_md)]) == 0
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["counts"] == {"high": 12, "medium": 1, "low": 0}
    assert len(data["findings"]) == 13
    assert "13 findings (12 high, 1 medium, 0 low)" in capsys.readouterr().out
    assert cli.main(["memory", "triage", str(INJECTED), "--fail-on", "high"]) == 3


def test_fail_on_respects_the_severity(tmp_path: Path) -> None:
    only_medium = tmp_path / "m"
    only_medium.mkdir()
    for name in ("pslist", "malfind"):
        shutil.copy(INJECTED / f"{name}.json", only_medium / f"{name}.json")
    (only_medium / "pslist.json").write_text("[]", encoding="utf-8")
    assert cli.main(["memory", "triage", str(only_medium), "--fail-on", "high"]) == 3  # injected-pe is high
    assert (
        cli.main(["memory", "triage", str(ROOT / "tests" / "fixtures" / "memory" / "clean"), "--fail-on", "low"]) == 0
    )


def test_memory_triage_without_pslist_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["memory", "triage", str(tmp_path)]) == 1
    assert "pslist.json is required" in capsys.readouterr().err


def test_memory_run_on_a_missing_image_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["memory", "run", "--image", str(tmp_path / "x.raw"), "--outdir", str(tmp_path / "o")]) == 1
    assert "memory image not found" in capsys.readouterr().err
