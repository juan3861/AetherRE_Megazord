from aether_re.language_profiles import analyze_language_profiles
from aether_re.project_audit import analyze_project


def test_static_profiles_collect_go_javascript_and_typescript_without_execution(tmp_path):
    (tmp_path / "cmd").mkdir()
    (tmp_path / "web").mkdir()
    (tmp_path / "cmd" / "main.go").write_text(
        'package main\nimport "fmt"\nfunc main() { fmt.Println("never run") }\n',
        encoding="utf-8",
    )
    (tmp_path / "web" / "app.js").write_text(
        'import util from "./util.js";\nexport function run() { return util(); }\n',
        encoding="utf-8",
    )
    (tmp_path / "web" / "util.ts").write_text(
        'export const util = (): string => "static";\n', encoding="utf-8"
    )

    report = analyze_language_profiles(tmp_path)

    assert report["schema"] == "static-language-profiles.v1"
    assert set(report["profiles"]) == {"go", "javascript", "typescript"}
    assert report["profiles"]["go"]["imports"][0]["target"] == '"fmt"'
    assert report["profiles"]["javascript"]["imports"][0]["target"] == "./util.js"
    assert report["profiles"]["typescript"]["modules"][0]["path"] == "web/util.ts"
    assert all(profile["executed"] is False for profile in report["profiles"].values())
    assert "equivalência semântica" in report["limitations"][0]


def test_project_audit_includes_static_language_profiles_and_keeps_them_heuristic(tmp_path):
    (tmp_path / "service.go").write_text("package service\nfunc Serve() {}\n", encoding="utf-8")
    (tmp_path / "client.ts").write_text("export function client() {}\n", encoding="utf-8")

    report = analyze_project(tmp_path)

    assert set(report["source"]["language_profiles"]["profiles"]) == {"go", "typescript"}
    assert {"go", "typescript"}.issubset(report["scope"]["analyzed_languages"])
    assert {"go", "typescript"}.isdisjoint(report["scope"]["excluded_languages"])
    assert report["source"]["language_profiles"]["analysis_kind"] == "lexical_heuristic"
