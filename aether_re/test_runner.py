"""Hermetic pytest launcher policy for reproducible project verification."""

from __future__ import annotations

import os
from collections.abc import Mapping


def isolated_pytest_environment(parent: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a copy that prevents ambient third-party pytest plugins loading."""
    environment = dict(os.environ if parent is None else parent)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return environment
