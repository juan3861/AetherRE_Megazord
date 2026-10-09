import sys

from aether_re.doctor import diagnose_tools


def test_doctor_discovers_running_python_without_claiming_integration():
    report = diagnose_tools()
    assert report["schema"] == "megazord-doctor.v1"
    assert report["tools"]["python"]["available"] is True
    assert report["tools"]["python"]["path"]
    assert isinstance(report["python_modules"]["elftools"]["available"], bool)
    assert "integração/análise" in report["limitations"][0]
