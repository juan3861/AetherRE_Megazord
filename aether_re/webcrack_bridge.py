"""
AetherRE SOTA Webcrack Bridge
=============================
Integrates webcrack 2.16.0 for enterprise-grade JavaScript reverse engineering:
- Automated Webpack, Browserify, and Rollup bundle unbundling and file splitting
- Control flow un-flattening and dead code removal
- Automated string array deobfuscation and decoder function inlining
- Modern ES6 syntax recovery
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class WebcrackModuleInfo:
    id: str
    path: str
    size: int


@dataclass
class WebcrackResult:
    input_path: str
    output_dir: str
    success: bool
    is_bundle: bool
    bundle_type: str
    module_count: int
    modules: List[WebcrackModuleInfo]
    deobfuscated_code: str
    elapsed_ms: float
    original_size: int = 0
    deobfuscated_size: int = 0
    error_message: Optional[str] = None


class WebcrackBridge:
    """Industrial bridge for Webcrack JS deobfuscation and unbundling."""

    DEFAULT_WORKER_PATH = Path(__file__).resolve().parent.parent / "tools" / "webcrack_worker.cjs"

    def __init__(self, node_path: str = "node", worker_path: Optional[str | Path] = None):
        self.node_path = node_path
        self.worker_path = Path(worker_path) if worker_path else self.DEFAULT_WORKER_PATH
        if not self.worker_path.exists():
            raise FileNotFoundError(f"Webcrack worker script not found at: {self.worker_path}")

    def deobfuscate(
        self,
        input_js_path: str | Path,
        output_dir: Optional[str | Path] = None,
        timeout_seconds: int = 120,
    ) -> WebcrackResult:
        """Deobfuscates, un-flattens, and unpacks a JS file using webcrack."""
        input_path = Path(input_js_path).resolve()
        if not input_path.exists():
            raise FileNotFoundError(f"Target JS file not found: {input_path}")

        if output_dir:
            out_dir = Path(output_dir).resolve()
            out_dir.mkdir(parents=True, exist_ok=True)
        else:
            out_dir = Path(tempfile.mkdtemp(prefix="aether_webcrack_"))

        cmd = [
            self.node_path,
            str(self.worker_path),
            str(input_path),
            str(out_dir),
        ]

        start_time = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            elapsed = (time.time() - start_time) * 1000.0

            manifest_path = out_dir / "webcrack_manifest.json"
            deobf_path = out_dir / "deobfuscated.js"

            if proc.returncode != 0 or not manifest_path.exists():
                err_text = proc.stderr.strip() or proc.stdout.strip() or f"Process failed with exit code {proc.returncode}"
                return WebcrackResult(
                    input_path=str(input_path),
                    output_dir=str(out_dir),
                    success=False,
                    is_bundle=False,
                    bundle_type="none",
                    module_count=0,
                    modules=[],
                    deobfuscated_code="",
                    elapsed_ms=elapsed,
                    error_message=err_text,
                )

            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)

            deobf_code = ""
            if deobf_path.exists():
                with open(deobf_path, "r", encoding="utf-8", errors="replace") as f:
                    deobf_code = f.read()

            modules = [
                WebcrackModuleInfo(
                    id=m.get("id", ""),
                    path=m.get("path", ""),
                    size=m.get("size", 0),
                )
                for m in manifest_data.get("modules", [])
            ]

            return WebcrackResult(
                input_path=str(input_path),
                output_dir=str(out_dir),
                success=True,
                is_bundle=manifest_data.get("is_bundle", False),
                bundle_type=manifest_data.get("bundle_type", "none"),
                module_count=manifest_data.get("module_count", len(modules)),
                modules=modules,
                deobfuscated_code=deobf_code,
                elapsed_ms=manifest_data.get("elapsed_ms", elapsed),
                original_size=manifest_data.get("original_size", 0),
                deobfuscated_size=manifest_data.get("deobfuscated_size", len(deobf_code)),
            )

        except subprocess.TimeoutExpired:
            return WebcrackResult(
                input_path=str(input_path),
                output_dir=str(out_dir),
                success=False,
                is_bundle=False,
                bundle_type="none",
                module_count=0,
                modules=[],
                deobfuscated_code="",
                elapsed_ms=(time.time() - start_time) * 1000.0,
                error_message=f"Webcrack execution timed out after {timeout_seconds}s",
            )
        except Exception as ex:
            return WebcrackResult(
                input_path=str(input_path),
                output_dir=str(out_dir),
                success=False,
                is_bundle=False,
                bundle_type="none",
                module_count=0,
                modules=[],
                deobfuscated_code="",
                elapsed_ms=(time.time() - start_time) * 1000.0,
                error_message=f"Webcrack exception: {str(ex)}",
            )
