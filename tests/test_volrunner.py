"""Running Volatility 3 in a child process: fake runs for every failure path, plus the real one."""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

import pytest

from dfir_toolkit import memory, volrunner
from dfir_toolkit._io import InputError

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "memory" / "injected"
HAS_VOL = importlib.util.find_spec("volatility3") is not None

FAKE_VOL = """\
import sys, pathlib
plugin = sys.argv[-1].rsplit(".", 1)[-1].lower()
mode = pathlib.Path(sys.argv[0]).with_suffix(".mode").read_text().strip()
if mode == "fail":
    sys.stderr.write("Unsatisfied requirement plugins.PsList.kernel.layer_name\\n")
    sys.exit(1)
if mode == "garbage":
    print("not json at all")
    sys.exit(0)
if mode == "hang":
    import time
    time.sleep(30)
print(pathlib.Path(sys.argv[0]).with_name(plugin + ".json").read_text())
"""


def fake_vol(tmp_path: Path, mode: str) -> tuple[str, ...]:
    """A stand-in Volatility that prints the fixtures, fails, prints garbage or hangs."""
    script = tmp_path / "fakevol.py"
    script.write_text(FAKE_VOL, encoding="utf-8")
    (tmp_path / "fakevol.mode").write_text(mode, encoding="utf-8")
    for p in memory.PLUGINS:
        (tmp_path / f"{p}.json").write_text((FIXTURES / f"{p}.json").read_text(encoding="utf-8"), encoding="utf-8")
    return (sys.executable, str(script))


@pytest.fixture
def image(tmp_path: Path) -> Path:
    """A placeholder image file (zeros)."""
    path = tmp_path / "image.raw"
    path.write_bytes(b"\0" * 4096)
    return path


def test_vol_command() -> None:
    cmd = volrunner.vol_command("windows.pslist.PsList", Path("m.raw"), Path("c"), True, ("vol",))
    assert cmd == ["vol", "-q", "-r", "json", "--cache-path", "c", "--offline", "-f", "m.raw", "windows.pslist.PsList"]
    assert "--offline" not in volrunner.vol_command("p", None, Path("c"), False, ("vol",))


def test_successful_run_writes_every_plugin_atomically(tmp_path: Path, image: Path) -> None:
    out = tmp_path / "out"
    runs = volrunner.run_plugins(image, out, vol=fake_vol(tmp_path, "ok"))
    assert [r.plugin for r in runs] == list(volrunner.VOL_PLUGINS)
    assert {r.plugin: r.rows for r in runs}["pslist"] == 19
    assert sorted(p.name for p in out.glob("*.json")) == sorted(f"{p}.json" for p in memory.PLUGINS)
    assert list(out.glob(".*.partial")) == []
    assert len(memory.triage(memory.load_directory(out))) == 13


def test_a_failing_plugin_raises_with_stderr_and_leaves_no_output(tmp_path: Path, image: Path) -> None:
    out = tmp_path / "out"
    with pytest.raises(volrunner.VolatilityError, match="exited with 1: Unsatisfied requirement"):
        volrunner.run_plugins(image, out, ("pslist",), vol=fake_vol(tmp_path, "fail"))
    assert [p.name for p in out.iterdir() if p.is_file()] == []


def test_unparseable_output_is_discarded(tmp_path: Path, image: Path) -> None:
    out = tmp_path / "out"
    with pytest.raises(InputError, match="no JSON list"):
        volrunner.run_plugins(image, out, ("pslist",), vol=fake_vol(tmp_path, "garbage"))
    assert [p.name for p in out.iterdir() if p.is_file()] == []


def test_a_hung_plugin_times_out(tmp_path: Path, image: Path) -> None:
    out = tmp_path / "out"
    with pytest.raises(volrunner.VolatilityError, match="timed out after 1 s"):
        volrunner.run_plugins(image, out, ("pslist",), timeout_s=1.0, vol=fake_vol(tmp_path, "hang"))
    assert [p.name for p in out.iterdir() if p.is_file()] == []


def test_a_missing_executable_is_reported(tmp_path: Path, image: Path) -> None:
    with pytest.raises(volrunner.VolatilityError, match="cannot start Volatility"):
        volrunner.run_plugins(image, tmp_path / "o", ("pslist",), vol=(str(tmp_path / "no-such-vol.exe"),))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [({"plugins": ("yarascan",)}, "unknown plugins"), ({"timeout_s": 0.0}, "timeout must be positive")],
)
def test_bad_arguments_are_rejected(tmp_path: Path, image: Path, kwargs: dict[str, object], message: str) -> None:
    with pytest.raises(InputError, match=message):
        volrunner.run_plugins(image, tmp_path / "o", **kwargs)  # type: ignore[arg-type]


def test_missing_image_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="memory image not found"):
        volrunner.run_plugins(tmp_path / "none.raw", tmp_path / "o")


def _string_constants(path: Path) -> set[str]:
    """Every string literal in a Python source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


@pytest.mark.vol
@pytest.mark.skipif(not HAS_VOL, reason="volatility3 not installed (pip install -e '.[vol]')")
@pytest.mark.parametrize("plugin", memory.PLUGINS)
def test_installed_volatility_declares_the_columns_we_read(plugin: str) -> None:
    spec = importlib.util.find_spec("volatility3")
    assert spec is not None
    assert spec.submodule_search_locations is not None
    base = Path(next(iter(spec.submodule_search_locations))) / "framework" / "plugins"
    module = volrunner.VOL_PLUGINS[plugin].split(".")[:-1]
    source = base.joinpath(*module).with_suffix(".py")
    assert memory.REQUIRED_COLUMNS[plugin] <= _string_constants(source)


@pytest.mark.vol
@pytest.mark.skipif(not HAS_VOL, reason="volatility3 not installed (pip install -e '.[vol]')")
def test_real_volatility_rejects_a_non_image_cleanly(tmp_path: Path, image: Path) -> None:
    out = tmp_path / "out"
    with pytest.raises(
        volrunner.VolatilityError, match=r"(?s)exited with 1: .*Unable to validate the plugin requirements"
    ):
        volrunner.run_plugins(image, out, ("pslist",), timeout_s=180.0, offline=True)
    assert [p.name for p in out.iterdir() if p.is_file()] == []
