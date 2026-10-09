import os

from aether_re.test_runner import isolated_pytest_environment


def test_isolated_pytest_environment_disables_external_autoload_without_mutating_parent():
    parent = {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "0", "KEEP": "yes"}
    environment = isolated_pytest_environment(parent)
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert environment["KEEP"] == "yes"
    assert parent["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "0"
