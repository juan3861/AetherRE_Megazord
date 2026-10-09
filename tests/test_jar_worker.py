from pathlib import Path

from aether_re.jar_worker import JarWorkerSpec, probe_jar_worker


def test_jar_worker_rejects_invalid_hashes_without_launching(tmp_path: Path):
    java = tmp_path / "java.exe"
    archive = tmp_path / "tool.jar"
    java.write_bytes(b"java")
    archive.write_bytes(b"jar")
    result = probe_jar_worker(JarWorkerSpec("tool", java, "x" * 64, archive, "y" * 64, "1.0", "Apache-2.0"))
    assert result["available"] is False
    assert "java_hash_mismatch" in result["errors"]
    assert "archive_hash_mismatch" in result["errors"]


def test_jar_worker_rejects_shell_syntax_before_launching(tmp_path: Path):
    java = tmp_path / "java.exe"
    archive = tmp_path / "tool.jar"
    java.write_bytes(b"java")
    archive.write_bytes(b"jar")
    import hashlib

    result = probe_jar_worker(JarWorkerSpec(
        "tool", java, hashlib.sha256(b"java").hexdigest(), archive,
        hashlib.sha256(b"jar").hexdigest(), "1.0", "Apache-2.0", version_args=("--version;bad",),
    ))
    assert result["available"] is False
    assert result["errors"] == ["worker_probe_arguments_invalid"]
