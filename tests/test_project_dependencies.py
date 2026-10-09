import json

from aether_re.project_dependencies import audit_project_dependencies, write_project_dependency_report


def test_dependency_audit_covers_python_node_and_c_without_execution(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.py").write_text("import requests\nimport localmod\n", encoding="utf-8")
    (root / "src" / "main.js").write_text("const x = require('lodash');\n", encoding="utf-8")
    (root / "src" / "main.c").write_text("#include <stdio.h>\n#include \"local.h\"\n", encoding="utf-8")
    (root / "requirements.txt").write_text("requests==2.32.0\nunused==1.0\n", encoding="utf-8")
    (root / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.0.0"}}), encoding="utf-8")
    report = audit_project_dependencies(root)
    assert report["schema"] == "project-dependency-audit.v1"
    assert report["status"] == "observed"
    assert any(item["normalized"] == "requests" and item["state"] == "declared_and_observed" for item in report["dependencies"])
    assert any(item["normalized"] == "unused" and item["state"] == "declared_not_observed" for item in report["dependencies"])
    assert any(item["normalized"] == "lodash" and item["state"] == "declared_and_observed" for item in report["dependencies"])
    assert any(item["normalized"] == "stdio" and item["ecosystem"] == "c" for item in report["observed"])
    assert "executado" in report["limitations"][-1]
    out = tmp_path / "dependencies.json"
    write_project_dependency_report(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == report["schema"]


def test_dependency_audit_rejects_malformed_toml_without_execution(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project\nname = 'broken'\n", encoding="utf-8")
    report = audit_project_dependencies(root)
    assert report["status"] == "invalid"
    assert any(item["code"] == "manifest_parse_error" for item in report["errors"])


def test_dependency_audit_rejects_missing_root_without_traceback(tmp_path):
    report = audit_project_dependencies(tmp_path / "missing")
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "root_missing"


def test_dependency_audit_rejects_malformed_vcpkg_dependency_shape(tmp_path):
    (tmp_path / "vcpkg.json").write_text(json.dumps({"dependencies": [42]}), encoding="utf-8")
    report = audit_project_dependencies(tmp_path)
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "manifest_invalid_dependency"
