from types import SimpleNamespace
from pathlib import Path
import pytest


@pytest.mark.parametrize("module_name", [
    "benchmark_cpp_poly_ground_truth", "benchmark_multi_poly_ground_truth",
    "benchmark_tinyexpr_ground_truth", "benchmark_all_exports_ground_truth",
])
def test_failed_decompiler_does_not_exit_success(module_name,tmp_path,monkeypatch):
    import importlib
    module = importlib.import_module("tools."+module_name)
    for path in ["cpp_poly/poly_test.dll","cpp_poly/poly_test.cpp","cpp_poly/multi_poly.dll",
                 "cpp_poly/multi_poly.cpp","tinyexpr/tinyexpr.dll","tinyexpr/tinyexpr.c",
                 "cjson/cjson.dll","cjson/cJSON.c"]:
        target = tmp_path / "external_test_repos" / path
        target.parent.mkdir(parents=True,exist_ok=True)
        if path.endswith(".dll"):
            target.write_bytes((Path(__file__).resolve().parents[1] / "external_test_repos/cpp_poly/multi_poly.dll").read_bytes())
        else:
            target.write_text("int owned(void){return 1;}")
    class FailedBridge:
        def decompile_binary(self,*args,**kwargs):
            return SimpleNamespace(success=False,functions={},error_message="worker_timeout")
    monkeypatch.setattr(module,"GhidraHeadlessBridge",FailedBridge)
    monkeypatch.chdir(tmp_path)
    if hasattr(module,"PROJECT_ROOT"):
        monkeypatch.setattr(module,"PROJECT_ROOT",tmp_path)
    assert module.main() != 0
