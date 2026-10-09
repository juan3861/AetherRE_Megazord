from pathlib import Path

from aether_re.adapters import ghidra


def test_default_ghidra_home_is_relative_to_the_checkout(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    module_path = tmp_path / "relocated" / "aether_re" / "adapters" / "ghidra.py"
    monkeypatch.setattr(ghidra, "__file__", str(module_path))

    expected = module_path.resolve().parents[2] / "tools" / "ghidra_12.1.2_PUBLIC"
    assert ghidra.GhidraAdapter().ghidra_home == expected


def test_ghidra_adapter_uses_direct_java_without_shell_and_clears_injected_options(
    monkeypatch, tmp_path: Path
):
    ghidra_home = tmp_path / "ghidra with spaces"
    utility_jar = ghidra_home / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
    utility_jar.parent.mkdir(parents=True)
    utility_jar.write_bytes(b"not a real jar; command construction only")
    java_home = tmp_path / "jdk with spaces"
    java = java_home / "bin" / "java.exe"
    java.parent.mkdir(parents=True)
    java.write_bytes(b"fake java executable")
    target = tmp_path / "authorized input.exe"
    target.write_bytes(b"MZ")
    out_dir = tmp_path / "run with spaces"

    captured = {}

    def fake_run_bounded(command, **kwargs):
        captured["command"] = [str(item) for item in command]
        captured["kwargs"] = kwargs
        captured["env"] = dict(kwargs["env"])
        output = Path(captured["env"]["AETHER_GHIDRA_OUT"])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("/* entry @ 0x1000 */\nvoid entry(void) {}\n", encoding="utf-8")
        return {
            "returncode": 0,
            "stdout": "Exported 1 functions\nAETHER_GHIDRA_SUMMARY attempted=1 succeeded=1 failed=0 truncated=false limit=2",
            "stderr": "",
            "timed_out": False,
        }

    monkeypatch.setattr(ghidra, "run_bounded", fake_run_bounded)
    monkeypatch.setenv("AETHER_GHIDRA_MAX_FUNCTIONS", "2")
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-javaagent:untrusted.jar")
    monkeypatch.setenv("_JAVA_OPTIONS", "-Duser.home=attacker")
    monkeypatch.setenv("JDK_JAVA_OPTIONS", "-Djava.security.manager=allow")
    monkeypatch.setenv("CLASSPATH", "attacker.jar")

    adapter = ghidra.GhidraAdapter(ghidra_home=str(ghidra_home), java_home=str(java_home))
    result = adapter.analyze(target, out_dir)

    command = captured["command"]
    assert command[0] == str(java)
    assert "-Djava.system.class.loader=ghidra.GhidraClassLoader" in command
    assert command[command.index("-cp") + 1] == str(utility_jar)
    assert command[command.index("-cp") + 2 : command.index("-cp") + 4] == [
        "ghidra.Ghidra",
        "ghidra.app.util.headless.AnalyzeHeadless",
    ]
    assert command[command.index("-import") + 1] == str(target)
    assert captured["env"]["AETHER_GHIDRA_MAX_FUNCTIONS"] == "2"
    assert all(not item.lower().endswith((".bat", ".cmd")) for item in command)
    assert "cmd.exe" not in command[0].lower()
    assert captured["kwargs"].get("shell") is False
    assert not {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"}.intersection(
        captured["env"]
    )
    assert result["ok"] is True
    assert result["produced_evidence"] is True
    assert result["extraction_status"] == "complete"
    assert result["attempted_functions"] == 1
    assert Path(result["decompiled_path"]).is_file()


def test_ghidra_availability_requires_java_and_utility_jar(tmp_path: Path):
    ghidra_home = tmp_path / "ghidra"
    java_home = tmp_path / "jdk"
    adapter = ghidra.GhidraAdapter(ghidra_home=str(ghidra_home), java_home=str(java_home))

    utility_jar = ghidra_home / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
    utility_jar.parent.mkdir(parents=True)
    utility_jar.write_bytes(b"placeholder")
    assert adapter.available() is False

    java = java_home / "bin" / "java.exe"
    java.parent.mkdir(parents=True)
    java.write_bytes(b"placeholder")
    assert adapter.available() is True

    utility_jar.unlink()
    assert adapter.available() is False


def test_timeout_preserves_partial_output_without_publishing_it_as_complete_evidence(
    monkeypatch, tmp_path: Path
):
    ghidra_home = tmp_path / "ghidra"
    utility_jar = ghidra_home / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
    utility_jar.parent.mkdir(parents=True)
    utility_jar.write_bytes(b"placeholder")
    java_home = tmp_path / "jdk"
    java = java_home / "bin" / "java.exe"
    java.parent.mkdir(parents=True)
    java.write_bytes(b"placeholder")
    target = tmp_path / "input.exe"
    target.write_bytes(b"MZ")
    out_dir = tmp_path / "run"

    def timed_out_run(command, **kwargs):
        output = Path(kwargs["env"]["AETHER_GHIDRA_OUT"])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("/* partial @ 0x1000 */\nvoid partial(void) {}\n", encoding="utf-8")
        return {
            "returncode": -1,
            "stdout": "Analysis stopped by timeout",
            "stderr": "",
            "timed_out": True,
            "resource_exceeded": False,
        }

    monkeypatch.setattr(ghidra, "run_bounded", timed_out_run)
    result = ghidra.GhidraAdapter(ghidra_home=str(ghidra_home), java_home=str(java_home)).analyze(
        target, out_dir
    )

    assert result["ok"] is False
    assert result["partial"] is True
    assert result["produced_evidence"] is False
    assert "decompiled_path" not in result
    assert Path(result["partial_decompiled_path"]).is_file()


def test_function_cap_is_explicitly_reported_as_partial_output(monkeypatch, tmp_path: Path):
    ghidra_home = tmp_path / "ghidra"
    utility_jar = ghidra_home / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
    utility_jar.parent.mkdir(parents=True)
    utility_jar.write_bytes(b"placeholder")
    java_home = tmp_path / "jdk"
    java = java_home / "bin" / "java.exe"
    java.parent.mkdir(parents=True)
    java.write_bytes(b"placeholder")
    target = tmp_path / "input.exe"
    target.write_bytes(b"MZ")
    out_dir = tmp_path / "run"

    def truncated_run(command, **kwargs):
        output = Path(kwargs["env"]["AETHER_GHIDRA_OUT"])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("/* f1 @ 0x1000 */\nvoid f1(void) {}\n", encoding="utf-8")
        return {
            "returncode": 0,
            "stdout": "Exported 2 functions\nAETHER_GHIDRA_SUMMARY attempted=2 succeeded=2 failed=0 truncated=true limit=2",
            "stderr": "",
            "timed_out": False,
        }

    monkeypatch.setattr(ghidra, "run_bounded", truncated_run)
    monkeypatch.setenv("AETHER_GHIDRA_MAX_FUNCTIONS", "2")
    result = ghidra.GhidraAdapter(ghidra_home=str(ghidra_home), java_home=str(java_home)).analyze(
        target, out_dir
    )

    assert result["ok"] is True
    assert result["produced_evidence"] is True
    assert result["partial"] is True
    assert result["extraction_status"] == "truncated"
    assert result["truncated"] is True
    assert result["max_functions"] == 2
    assert result["attempted_functions"] == 2
    assert result["exported_functions"] == 2
