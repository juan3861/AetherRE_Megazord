import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from aether_re import release_inventory
from megazord import main


def _run_cli(monkeypatch, root: Path, files: list[str], out: str, *extra: str) -> int:
    monkeypatch.setattr(
        sys,
        "argv",
        ["megazord.py", "release-inventory", "--root", str(root), "--files", *files, "--out", out, *extra],
    )
    try:
        return main()
    except SystemExit as exc:
        return int(exc.code)


def test_release_inventory_records_hashes_missing_files_and_unverified_claims(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    present = root / "evidence" / "proof.bin"
    present.parent.mkdir()
    payload = b"explicitly listed evidence bytes"
    present.write_bytes(payload)

    result = _run_cli(
        monkeypatch,
        root,
        ["evidence/proof.bin", "evidence/not-yet-collected.json"],
        "inventory.json",
        "--gate-claim",
        "F00=PARCIALMENTE QUITADA",
        "--gate-claim",
        "F08=NÃO COMPROVADA",
    )

    assert result == 0
    inventory = json.loads((root / "inventory.json").read_text(encoding="utf-8"))
    assert inventory["schema"] == "release-inventory.v1"
    assert inventory["inventory_status"] == "PARTIAL_INVENTORY"
    assert inventory["files"] == [
        {
            "path": "evidence/not-yet-collected.json",
            "present": False,
            "size_bytes": None,
            "sha256": None,
        },
        {
            "path": "evidence/proof.bin",
            "present": True,
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        },
    ]
    assert inventory["gate_claims"] == [
        {"gate": "F00", "claimed_status": "PARCIALMENTE QUITADA", "verified": False},
        {"gate": "F08", "claimed_status": "NÃO COMPROVADA", "verified": False},
    ]
    assert inventory["certification_status"] == "NOT_CERTIFIED"
    assert inventory["promoted_gates"] == []
    assert inventory["gate_truth_recalculated"] is False
    assert inventory["release_manifest_generated"] is False
    assert not (root / "release-manifest.v1.json").exists()


def test_release_inventory_is_recalculable_for_the_same_root_and_file_set(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "evidence.bin").write_bytes(b"recalculate these bytes")

    first_result = _run_cli(monkeypatch, root, ["evidence.bin", "missing.bin"], "first.json")
    second_result = _run_cli(monkeypatch, root, ["evidence.bin", "missing.bin"], "second.json")

    assert first_result == second_result == 0
    first = json.loads((root / "first.json").read_text(encoding="utf-8"))
    second = json.loads((root / "second.json").read_text(encoding="utf-8"))
    assert first == second


@pytest.mark.parametrize(
    "relative_path",
    ["../outside.bin", "nested/../../outside.bin", r"..\outside.bin", r"C:\outside.bin", r"C:outside.bin"],
)
def test_release_inventory_rejects_traversal_and_drive_paths(tmp_path, monkeypatch, relative_path):
    root = tmp_path / "bundle"
    root.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"must not be inventoried")

    result = _run_cli(monkeypatch, root, [relative_path], "inventory.json")

    assert result == 3
    assert not (root / "inventory.json").exists()


def test_release_inventory_rejects_output_escape(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "inside.bin").write_bytes(b"in scope")

    result = _run_cli(monkeypatch, root, ["inside.bin"], "../outside-inventory.json")

    assert result == 3
    assert not (tmp_path / "outside-inventory.json").exists()


def test_release_inventory_output_is_create_only(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "inside.bin").write_bytes(b"in scope")
    output = root / "inventory.json"
    output.write_text("preserve existing report", encoding="utf-8")

    result = _run_cli(monkeypatch, root, ["inside.bin"], "inventory.json")

    assert result == 3
    assert output.read_text(encoding="utf-8") == "preserve existing report"


def test_release_inventory_rejects_a_symlinked_input(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    actual = root / "actual.bin"
    actual.write_bytes(b"bytes")
    linked = root / "linked.bin"
    try:
        linked.symlink_to(actual)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    result = _run_cli(monkeypatch, root, ["linked.bin"], "inventory.json")

    assert result == 3
    assert not (root / "inventory.json").exists()


def test_release_inventory_rejects_input_reached_through_symlinked_parent(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    actual_dir = root / "actual"
    actual_dir.mkdir()
    (actual_dir / "proof.bin").write_bytes(b"bytes")
    alias = root / "alias"
    try:
        alias.symlink_to(actual_dir, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    result = _run_cli(monkeypatch, root, ["alias/proof.bin"], "inventory.json")

    assert result == 3
    assert not (root / "inventory.json").exists()


def test_release_inventory_rejects_output_reached_through_symlinked_parent(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "inside.bin").write_bytes(b"bytes")
    real_dir = root / "real-reports"
    real_dir.mkdir()
    alias = root / "report-alias"
    try:
        alias.symlink_to(real_dir, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    result = _run_cli(monkeypatch, root, ["inside.bin"], "report-alias/inventory.json")

    assert result == 3
    assert not (real_dir / "inventory.json").exists()


def test_release_inventory_rejects_a_hardlinked_input(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    actual = root / "actual.bin"
    actual.write_bytes(b"bytes")
    linked = root / "linked.bin"
    try:
        linked.hardlink_to(actual)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    result = _run_cli(monkeypatch, root, ["linked.bin"], "inventory.json")

    assert result == 3
    assert not (root / "inventory.json").exists()


def test_release_inventory_rejects_symlinked_root(tmp_path, monkeypatch):
    actual_root = tmp_path / "actual"
    actual_root.mkdir()
    (actual_root / "inside.bin").write_bytes(b"bytes")
    root_alias = tmp_path / "root-alias"
    try:
        root_alias.symlink_to(actual_root, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    result = _run_cli(monkeypatch, root_alias, ["inside.bin"], "inventory.json")

    assert result == 3
    assert not (actual_root / "inventory.json").exists()


@pytest.mark.parametrize("claim", ["F13=QUITADA", "F01=UNKNOWN", "F02=true"])
def test_release_inventory_rejects_invalid_gate_claims(tmp_path, monkeypatch, claim):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "inside.bin").write_bytes(b"bytes")

    result = _run_cli(monkeypatch, root, ["inside.bin"], "inventory.json", "--gate-claim", claim)

    assert result == 3
    assert not (root / "inventory.json").exists()


def test_release_inventory_rejects_duplicate_input_paths(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "inside.bin").write_bytes(b"bytes")

    result = _run_cli(monkeypatch, root, ["inside.bin", "./inside.bin"], "inventory.json")

    assert result == 3
    assert not (root / "inventory.json").exists()


@pytest.mark.parametrize(
    "aliases",
    [
        ["Evidence.bin", "evidence.bin"],
        ["evidence.bin", "evidence.bin. "],
    ],
)
def test_release_inventory_rejects_win32_name_aliases_on_every_host(tmp_path, monkeypatch, aliases):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "Evidence.bin").write_bytes(b"same Win32 name")

    result = _run_cli(monkeypatch, root, aliases, "inventory.json")

    assert result == 3
    assert not (root / "inventory.json").exists()


def test_release_inventory_rejects_output_input_win32_alias(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()

    result = _run_cli(monkeypatch, root, ["Inventory.json. "], "inventory.json")

    assert result == 3
    assert not (root / "inventory.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="8.3 aliases are a Win32 filesystem feature")
def test_release_inventory_rejects_existing_8dot3_alias_by_physical_identity(tmp_path, monkeypatch):
    import ctypes

    root = tmp_path / "bundle"
    root.mkdir()
    actual = root / "evidence-with-a-deliberately-long-name.bin"
    actual.write_bytes(b"same physical file")

    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetShortPathNameW(str(actual), buffer, len(buffer))
    if not length or length >= len(buffer):
        pytest.skip("GetShortPathNameW did not return an alias")
    short_name = Path(buffer.value).name
    if short_name.casefold() == actual.name.casefold():
        pytest.skip("8.3 aliases are disabled on this volume")

    result = _run_cli(monkeypatch, root, [actual.name, short_name], "inventory.json")

    assert result == 3
    assert not (root / "inventory.json").exists()


def test_release_inventory_rejects_repeated_physical_identity(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "first.bin").write_bytes(b"first")
    (root / "second.bin").write_bytes(b"second")
    real_fingerprint = release_inventory._fingerprint

    def same_identity(path, *, relative_name):
        entry, _identity = real_fingerprint(path, relative_name=relative_name)
        return entry, (123, 456)

    monkeypatch.setattr(release_inventory, "_fingerprint", same_identity)

    result = _run_cli(monkeypatch, root, ["first.bin", "second.bin"], "inventory.json")

    assert result == 3
    assert not (root / "inventory.json").exists()


def test_release_inventory_does_not_allow_output_to_be_one_of_its_inputs(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "inside.bin").write_bytes(b"bytes")

    result = _run_cli(monkeypatch, root, ["inventory.json"], "inventory.json")

    assert result == 3
    assert not (root / "inventory.json").exists()
