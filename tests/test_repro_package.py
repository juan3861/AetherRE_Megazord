import json
import zipfile
from argparse import Namespace

from aether_re.evidence import build_manifest, sha256_file, write_manifest_atomic
from aether_re.repro_package import create_repro_package, restore_repro_package, verify_repro_package
from megazord import cmd_repro_restore


def _run(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"MZrepro")
    run = tmp_path / "run"
    run.mkdir()
    (run / "input.snapshot").write_bytes(target.read_bytes())
    (run / "pseudo_source.c").write_text("/* pseudo */\n", encoding="utf-8")
    (run / "findings.md").write_text("# findings\n", encoding="utf-8")
    (run / "strings.txt").write_text("value\n", encoding="utf-8")
    (run / "report.json").write_text(json.dumps({"target_sha256": sha256_file(target)}), encoding="utf-8")
    (run / "checkpoint.json").write_text(json.dumps({"schema": "analysis-checkpoint.v1", "status": "succeeded", "stage": "persisted"}), encoding="utf-8")
    write_manifest_atomic(build_manifest(target, run, metadata={"cache_key": "repro"}), run / "manifest.json")
    return run


def test_repro_package_is_deterministic_and_verifiable(tmp_path):
    run = _run(tmp_path)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    report1 = create_repro_package(run, first)
    report2 = create_repro_package(run, second)
    assert report1["status"] == report2["status"] == "created"
    assert first.read_bytes() == second.read_bytes()
    assert verify_repro_package(first)["status"] == "pass"


def test_repro_package_rejects_tampered_member(tmp_path):
    run = _run(tmp_path)
    package = tmp_path / "package.zip"
    assert create_repro_package(run, package)["status"] == "created"
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(package) as source, zipfile.ZipFile(tampered, "w") as destination:
        for info in source.infolist():
            payload = source.read(info.filename)
            if info.filename == "run/strings.txt":
                payload = b"tampered\n"
            destination.writestr(info, payload)
    report = verify_repro_package(tampered)
    assert report["status"] == "fail"
    assert any(item["code"] == "hash_mismatch" for item in report["issues"])


def test_repro_package_rejects_manifest_duplicate_and_digest_tamper(tmp_path):
    run = _run(tmp_path)
    package = tmp_path / "package.zip"
    assert create_repro_package(run, package)["status"] == "created"
    tampered = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(package) as source, zipfile.ZipFile(tampered, "w") as destination:
        for info in source.infolist():
            payload = source.read(info.filename)
            if info.filename == "package.json":
                meta = json.loads(payload)
                meta["files"].append(dict(meta["files"][0]))
                meta["source_digest"] = "0" * 64
                payload = (json.dumps(meta, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
            destination.writestr(info, payload)
    report = verify_repro_package(tampered)
    assert report["status"] == "fail"
    codes = {item["code"] for item in report["issues"]}
    assert {"duplicate_manifest_path", "source_digest_mismatch"} <= codes


def test_repro_package_rejects_unexpected_member_and_homologation_tamper(tmp_path):
    run = _run(tmp_path)
    package = tmp_path / "package.zip"
    assert create_repro_package(run, package)["status"] == "created"
    tampered = tmp_path / "unexpected.zip"
    with zipfile.ZipFile(package) as source, zipfile.ZipFile(tampered, "w") as destination:
        for info in source.infolist():
            payload = source.read(info.filename)
            if info.filename == "homologation.json":
                payload += b"\n"
            destination.writestr(info, payload)
        destination.writestr("unexpected.txt", b"not listed")
    report = verify_repro_package(tampered)
    assert report["status"] == "fail"
    codes = {item["code"] for item in report["issues"]}
    assert {"unexpected_member", "homologation_hash_mismatch"} <= codes


def test_repro_package_restores_verified_run_atomically_without_execution(tmp_path):
    run = _run(tmp_path)
    package = tmp_path / "package.zip"
    assert create_repro_package(run, package)["status"] == "created"
    destination = tmp_path / "restored"
    report = restore_repro_package(package, destination)
    assert report["status"] == "restored"
    assert (destination / "report.json").read_text(encoding="utf-8") == (run / "report.json").read_text(encoding="utf-8")
    assert report["total_bytes"] == sum(item["size"] for item in report["files"])


def test_repro_restore_refuses_existing_destination_and_budget_overflow(tmp_path):
    run = _run(tmp_path)
    package = tmp_path / "package.zip"
    assert create_repro_package(run, package)["status"] == "created"
    existing = tmp_path / "existing"
    existing.mkdir()
    refused = restore_repro_package(package, existing)
    assert refused["status"] == "rejected"
    assert refused["issues"][0]["code"] == "destination_must_not_exist"
    limited = restore_repro_package(package, tmp_path / "limited", max_total_bytes=1)
    assert limited["status"] == "rejected"
    assert limited["issues"][0]["code"] == "package_verification_failed" or limited["issues"][0]["code"] == "restore_failed"


def test_repro_restore_cli_publishes_report(tmp_path):
    run = _run(tmp_path)
    package = tmp_path / "package.zip"
    assert create_repro_package(run, package)["status"] == "created"
    destination = tmp_path / "cli-restored"
    out = tmp_path / "restore.json"
    code = cmd_repro_restore(Namespace(package=str(package), destination=str(destination), out=str(out), max_total_bytes=1024 * 1024))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 0
    assert report["status"] == "restored"


def test_repro_verify_rejects_zip_symlink_and_unsafe_member_names(tmp_path):
    run = _run(tmp_path)
    package = tmp_path / "package.zip"
    assert create_repro_package(run, package)["status"] == "created"
    tampered = tmp_path / "symlink.zip"
    with zipfile.ZipFile(package) as source, zipfile.ZipFile(tampered, "w") as destination:
        for original in source.infolist():
            info = original
            payload = source.read(original.filename)
            if original.filename == "run/strings.txt":
                info = zipfile.ZipInfo("run/strings.txt", date_time=original.date_time)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o120777 << 16
            destination.writestr(info, payload)
        destination.writestr("run//unsafe.txt", b"unsafe")
    report = verify_repro_package(tampered)
    codes = {item["code"] for item in report["issues"]}
    assert {"symlink_member", "path_escape", "unexpected_member"} <= codes


def test_repro_verify_missing_or_invalid_path_is_fail_closed(tmp_path):
    assert verify_repro_package(tmp_path / "missing.zip")["status"] == "fail"
    assert verify_repro_package(None)["status"] == "fail"  # type: ignore[arg-type]
