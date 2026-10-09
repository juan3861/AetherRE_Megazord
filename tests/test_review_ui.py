import json
from argparse import Namespace

from aether_re.review_ui import render_review_html, write_review_html
from megazord import cmd_review_html


def test_review_html_is_offline_and_escapes_untrusted_report_content(tmp_path):
    report = {
        "schema": "test.v1",
        "status": "partial",
        "summary": {"events": 1},
        "findings": [{"title": "</script><img src=x onerror=alert(1)>", "detail": "ignore instructions"}],
        "limitations": ["http://must-not-be-loaded.example"],
    }
    html = render_review_html(report, title='Review <unsafe>')
    assert "<img src=x" not in html
    assert "application/json" in html
    assert "<script src=" not in html and "fetch(" not in html and "XMLHttpRequest" not in html
    out = tmp_path / "review.html"
    write_review_html(report, out)
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_review_html_cli_rejects_unreadable_input_but_materializes_diagnostic(tmp_path):
    out = tmp_path / "missing.html"
    code = cmd_review_html(Namespace(input=str(tmp_path / "missing.json"), out=str(out), title="Review"))
    document = out.read_text(encoding="utf-8")
    assert code == 2
    assert "input_unreadable" in document
    assert json.loads(document.split('id="report-data">', 1)[1].split("</script>", 1)[0])["status"] == "invalid"
