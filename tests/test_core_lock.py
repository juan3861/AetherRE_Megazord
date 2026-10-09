import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+) --hash=sha256:([0-9a-f]{64})$")


def test_core_lock_pins_declared_dependencies_with_hashes():
    direct = {
        re.split(r"[<>=!~]", line.strip(), maxsplit=1)[0].lower().replace("_", "-")
        for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    rows = [line for line in (ROOT / "requirements-core.lock").read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
    parsed = [PIN_RE.fullmatch(row) for row in rows]
    assert parsed and all(parsed)
    pinned = [match.group(1).lower().replace("_", "-") for match in parsed if match]
    assert len(pinned) == len(set(pinned))
    assert direct <= set(pinned)
    assert "cryptography" in direct
    assert "frida-tools" not in pinned


def test_frida_is_explicit_optional_profile():
    assert "frida-tools" in (ROOT / "requirements-frida.txt").read_text(encoding="utf-8")
    assert "frida-tools" not in (ROOT / "requirements.txt").read_text(encoding="utf-8")


def test_test_lock_includes_schema_validator_used_by_test_suite():
    lock = (ROOT / "requirements-test.lock").read_text(encoding="utf-8")
    assert "jsonschema==" in lock
    assert "referencing==" in lock
    assert "rpds-py==" in lock
