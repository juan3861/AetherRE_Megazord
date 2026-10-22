"""
AetherRE SOTA Ghidra Headless Bridge
====================================
Integrates NSA Ghidra Headless (12.1.4+) for industrial-grade binary decompilation,
C code recovery, AST construction, and High P-Code generation.
Runs completely headless with isolated OpenJDK 21 execution environment.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class GhidraFunctionInfo:
    name: str
    address: str
    success: bool
    params: int
    return_type: str
    decompiled_c: Optional[str] = None
    pcode_ops: List[str] = field(default_factory=list)


@dataclass
class GhidraDecompilationResult:
    binary_path: str
    success: bool
    total_functions: int
    decompiled_functions: int
    functions: Dict[str, GhidraFunctionInfo]
    full_c_source: str
    high_pcode_text: str
    elapsed_seconds: float
    error_message: Optional[str] = None


class GhidraHeadlessBridge:
    """Industrial headless wrapper for NSA Ghidra Decompiler."""

    DEFAULT_GHIDRA_PATH = Path(r"E:\AetherRE_Toolchain\ghidra_12.1.4_PUBLIC")
    DEFAULT_JDK_PATH = Path(r"E:\AetherRE_Toolchain\jdk-21")
    DEFAULT_SCRIPTS_DIR = Path(__file__).resolve().parent / "ghidra_scripts"

    def __init__(
        self,
        ghidra_home: Optional[str | Path] = None,
        jdk_home: Optional[str | Path] = None,
        scripts_dir: Optional[str | Path] = None,
    ):
        self.ghidra_home = Path(ghidra_home) if ghidra_home else self.DEFAULT_GHIDRA_PATH
        self.jdk_home = Path(jdk_home) if jdk_home else self.DEFAULT_JDK_PATH
        self.scripts_dir = Path(scripts_dir) if scripts_dir else self.DEFAULT_SCRIPTS_DIR

        self.headless_bat = self.ghidra_home / "support" / "analyzeHeadless.bat"
        if not self.headless_bat.exists():
            raise FileNotFoundError(f"Ghidra analyzeHeadless.bat not found at: {self.headless_bat}")

    def decompile_binary(
        self,
        binary_path: str | Path,
        timeout_seconds: int = 300,
        temp_work_dir: Optional[str | Path] = None,
        max_cpu: int = 4,
    ) -> GhidraDecompilationResult:
        """Runs Ghidra headless analysis on target binary, decompiling all functions to C and P-Code."""
        binary = Path(binary_path).resolve()
        if not binary.exists():
            raise FileNotFoundError(f"Target binary not found: {binary}")

        start_time = time.time()
        cleanup_temp = False

        if temp_work_dir:
            work_dir = Path(temp_work_dir).resolve()
            work_dir.mkdir(parents=True, exist_ok=True)
        else:
            work_dir = Path(tempfile.mkdtemp(prefix="aether_ghidra_"))
            cleanup_temp = True

        out_dir = work_dir / "output"
        out_dir.mkdir(parents=True, exist_ok=True)
        proj_dir = work_dir / "proj"
        proj_dir.mkdir(parents=True, exist_ok=True)
        proj_name = f"AetherProj_{binary.stem}"

        env = os.environ.copy()
        if self.jdk_home.exists():
            env["JAVA_HOME"] = str(self.jdk_home)
            env["PATH"] = f"{self.jdk_home / 'bin'};{env.get('PATH', '')}"

        cmd = [
            str(self.headless_bat),
            str(proj_dir),
            proj_name,
            "-import",
            str(binary),
            "-scriptPath",
            str(self.scripts_dir),
            "-max-cpu",
            str(max_cpu),
            "-deleteProject",
            "-okToDelete",
            "-postScript",
            "DecompileAllFunctions.java",
            str(out_dir),
        ]

        try:
            proc = subprocess.run(
                cmd,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            elapsed = time.time() - start_time

            summary_file = out_dir / "decompilation_summary.json"
            c_file = out_dir / "decompiled_all.c"
            pcode_file = out_dir / "high_pcode.txt"

            if not summary_file.exists():
                return GhidraDecompilationResult(
                    binary_path=str(binary),
                    success=False,
                    total_functions=0,
                    decompiled_functions=0,
                    functions={},
                    full_c_source="",
                    high_pcode_text="",
                    elapsed_seconds=elapsed,
                    error_message=f"Ghidra did not produce summary JSON. ExitCode: {proc.returncode}\nStderr: {proc.stderr[-1000:]}\nStdout: {proc.stdout[-1000:]}",
                )

            with open(summary_file, "r", encoding="utf-8") as f:
                summary_data = json.load(f)

            full_c_source = ""
            if c_file.exists():
                with open(c_file, "r", encoding="utf-8", errors="replace") as f:
                    full_c_source = f.read()

            high_pcode = ""
            if pcode_file.exists():
                with open(pcode_file, "r", encoding="utf-8", errors="replace") as f:
                    high_pcode = f.read()

            functions_dict: Dict[str, GhidraFunctionInfo] = {}
            for item in summary_data.get("functions", []):
                fname = item["name"]
                f_info = GhidraFunctionInfo(
                    name=fname,
                    address=item["address"],
                    success=item["success"],
                    params=item["params"],
                    return_type=item["return_type"],
                )
                functions_dict[fname] = f_info

            # Map function C snippets from decompiled_all.c
            if full_c_source:
                snippets = full_c_source.split("// Function: ")
                for snip in snippets[1:]:
                    lines = snip.split("\n", 1)
                    header = lines[0].strip()
                    body = lines[1].strip() if len(lines) > 1 else ""
                    # header: "cJSON_Delete @ 180001090"
                    fname = header.split(" @ ")[0].strip()
                    if fname in functions_dict:
                        functions_dict[fname].decompiled_c = body

            return GhidraDecompilationResult(
                binary_path=str(binary),
                success=True,
                total_functions=summary_data.get("total_functions", len(functions_dict)),
                decompiled_functions=summary_data.get("decompiled_functions", 0),
                functions=functions_dict,
                full_c_source=full_c_source,
                high_pcode_text=high_pcode,
                elapsed_seconds=elapsed,
            )

        except subprocess.TimeoutExpired:
            return GhidraDecompilationResult(
                binary_path=str(binary),
                success=False,
                total_functions=0,
                decompiled_functions=0,
                functions={},
                full_c_source="",
                high_pcode_text="",
                elapsed_seconds=timeout_seconds,
                error_message=f"Ghidra execution timed out after {timeout_seconds}s",
            )
        except Exception as ex:
            return GhidraDecompilationResult(
                binary_path=str(binary),
                success=False,
                total_functions=0,
                decompiled_functions=0,
                functions={},
                full_c_source="",
                high_pcode_text="",
                elapsed_seconds=time.time() - start_time,
                error_message=f"Exception during Ghidra execution: {str(ex)}",
            )
        finally:
            if cleanup_temp:
                try:
                    shutil.rmtree(work_dir, ignore_errors=True)
                except Exception:
                    pass
