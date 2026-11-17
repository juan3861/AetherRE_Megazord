import json
import hashlib
import subprocess
from types import SimpleNamespace
from pathlib import Path

import aether_re.ghidra_headless_bridge as module


def test_invalid_summary_preserves_input_and_worker_receipt(tmp_path, monkeypatch):
    home = tmp_path / "ghidra"
    launcher = home / "support/analyzeHeadless.bat"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("unused")
    utility = home / "Ghidra/Framework/Utility/lib/Utility.jar"
    utility.parent.mkdir(parents=True)
    utility.write_bytes(b"unused")
    jdk = tmp_path / "jdk"
    (jdk / "bin").mkdir(parents=True)
    (jdk / "bin/java.exe").write_bytes(b"unused")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"owned fixture")

    def bounded(command,**kwargs):
        (Path(command[-1]) / "decompilation_summary.json").write_text("{broken")
        return {"returncode":0,"stdout":"","stderr":"","timed_out":False,
                "resource_exceeded":False,"process_tree_contained":True,"capture_complete":True}

    monkeypatch.setattr(module,"run_bounded",bounded)
    result = module.GhidraHeadlessBridge(home,jdk).decompile_binary(target,temp_work_dir=tmp_path / "jobs")
    assert result.success is False
    assert result.target_sha256 == hashlib.sha256(b"owned fixture").hexdigest()
    assert result.worker_execution["returncode"] == 0
    assert result.worker_execution["process_tree_contained"] is True
    assert Path(result.artifact_dir).is_dir()


def test_failed_worker_artifacts_do_not_turn_into_success(tmp_path, monkeypatch):
    ghidra = tmp_path / "ghidra"
    launcher = ghidra / "support" / "analyzeHeadless.bat"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("unused", encoding="utf-8")
    utility = ghidra / "Ghidra/Framework/Utility/lib/Utility.jar"
    utility.parent.mkdir(parents=True)
    utility.write_bytes(b"unused")
    jdk = tmp_path / "jdk"
    (jdk / "bin").mkdir(parents=True)
    (jdk / "bin/java.exe").write_bytes(b"unused")
    work = tmp_path / "work"
    target = tmp_path / "owned.bin"
    target.write_bytes(b"owned fixture")

    def artifacts(command):
        out = Path(command[-1])
        out.mkdir(parents=True,exist_ok=True)
        (out / "decompilation_summary.json").write_text(json.dumps({
            "total_functions":1,"decompiled_functions":1,
            "functions":[{"name":"f","address":"401000","success":True}],
        }))
        (out / "decompiled_all.c").write_text("// Function: f @ 401000\nint f(){return 1;}")

    def bounded(*args,**kwargs):
        artifacts(args[0])
        return {"returncode":7,"stdout":"","stderr":"worker failed","timed_out":False,
                "resource_exceeded":False,"process_tree_contained":True,"capture_complete":True}

    def unbounded(*args,**kwargs):
        artifacts(args[0])
        return SimpleNamespace(returncode=7,stdout="",stderr="worker failed")

    monkeypatch.setattr(module,"run_bounded",bounded,raising=False)
    monkeypatch.setattr(module.subprocess,"run",unbounded)
    bridge = module.GhidraHeadlessBridge(ghidra,jdk)
    result = bridge.decompile_binary(target,temp_work_dir=work)
    assert result.success is False
    assert "7" in result.error_message


def test_bridge_requests_process_tree_and_bounded_capture(tmp_path, monkeypatch):
    home = tmp_path / "ghidra"
    launcher = home / "support/analyzeHeadless.bat"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("unused")
    utility = home / "Ghidra/Framework/Utility/lib/Utility.jar"
    utility.parent.mkdir(parents=True)
    utility.write_bytes(b"unused")
    jdk = tmp_path / "jdk"
    (jdk / "bin").mkdir(parents=True)
    (jdk / "bin/java.exe").write_bytes(b"unused")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"owned fixture")
    policy = {}

    def bounded(command,**kwargs):
        policy.update(kwargs)
        policy["command"] = command
        return {"returncode":-1,"stdout":"","stderr":"","timed_out":True,
                "resource_exceeded":False,"process_tree_contained":True,"capture_complete":True}

    def unbounded(command,**kwargs):
        raise subprocess.TimeoutExpired(command,kwargs.get("timeout",1))

    monkeypatch.setattr(module,"run_bounded",bounded,raising=False)
    monkeypatch.setattr(module.subprocess,"run",unbounded)
    result = module.GhidraHeadlessBridge(home,jdk).decompile_binary(target,timeout_seconds=3)
    assert result.success is False
    assert policy.get("require_process_tree") is True
    assert policy.get("timeout") == 3
    assert policy.get("output_limit_bytes",0) > 0
    assert str(policy["command"][0]).endswith("java.exe")
