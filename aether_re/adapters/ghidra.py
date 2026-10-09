"""Adapter Ghidra headless — decompilação real quando Ghidra estiver instalado."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

DEFAULT_JDK21 = r"C:\Program Files\Android\Android Studio\jbr"
DEFAULT_MAX_FUNCTIONS = 200
MAX_FUNCTIONS_LIMIT = 10000

from aether_re.adapters.base import Adapter
from aether_re.process import cpu_limit_from_env, memory_limit_from_env, run_bounded, timeout_from_env


class GhidraAdapter(Adapter):
    name = "ghidra"

    def __init__(self, ghidra_home: str | None = None, java_home: str | None = None) -> None:
        checkout_tool = Path(__file__).resolve().parents[2] / "tools" / "ghidra_12.1.2_PUBLIC"
        self.ghidra_home = Path(
            ghidra_home
            or os.environ.get("GHIDRA_HOME", "")
            or checkout_tool
        )
        self.java_home = Path(java_home or os.environ.get("GHIDRA_JAVA_HOME", "") or DEFAULT_JDK21)

    def _launcher(self) -> tuple[Path, Path] | None:
        java_name = "java.exe" if os.name == "nt" else "java"
        java = self.java_home / "bin" / java_name
        utility_jar = self.ghidra_home / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
        if not self.ghidra_home.is_dir() or not java.is_file() or not utility_jar.is_file():
            return None
        return java, utility_jar

    def available(self) -> bool:
        return self._launcher() is not None

    def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
        launcher = self._launcher()
        if not launcher:
            return {
                "ok": False,
                "available": False,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
                "error": "Ghidra runtime incompleto: confirme GHIDRA_HOME, Utility.jar e Java 21 em GHIDRA_JAVA_HOME",
            }
        java, utility_jar = launcher

        project_dir = out_dir / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)
        export_dir = out_dir / "ghidra_export"
        export_dir.mkdir(parents=True, exist_ok=True)
        isolated_dirs = {
            "home": out_dir / "ghidra_user_home",
            "settings": out_dir / "ghidra_settings",
            "cache": out_dir / "ghidra_cache",
            "tmp": out_dir / "ghidra_tmp",
        }
        for directory in isolated_dirs.values():
            directory.mkdir(parents=True, exist_ok=True)

        # Script mínimo embutido: exporta funções decompiladas
        script = out_dir / "ExportDecompiled.java"
        script.write_text(
            """
// @category AetherRE
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;

public class ExportDecompiled extends GhidraScript {
    public void run() throws Exception {
        String outPath = System.getenv("AETHER_GHIDRA_OUT");
        if (outPath == null) outPath = "decompiled.c";
        String limitText = System.getenv("AETHER_GHIDRA_MAX_FUNCTIONS");
        int maxFunctions = limitText == null ? 200 : Integer.parseInt(limitText);
        int attempted = 0;
        int succeeded = 0;
        int failed = 0;
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        boolean truncated;
        try (FileWriter fw = new FileWriter(outPath)) {
            while (it.hasNext() && attempted < maxFunctions) {
                Function f = it.next();
                attempted++;
                DecompileResults res = ifc.decompileFunction(f, 30, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    fw.write("/* " + f.getName() + " @ " + f.getEntryPoint() + " */\\n");
                    fw.write(res.getDecompiledFunction().getC());
                    fw.write("\\n\\n");
                    succeeded++;
                } else {
                    failed++;
                }
            }
            truncated = it.hasNext();
        } finally {
            ifc.dispose();
        }
        println("Exported " + succeeded + " functions");
        println("AETHER_GHIDRA_SUMMARY attempted=" + attempted + " succeeded=" + succeeded +
                " failed=" + failed + " truncated=" + truncated + " limit=" + maxFunctions);
    }
}
""".strip(),
            encoding="utf-8",
        )

        decompiled = export_dir / "decompiled.c"
        # Do not allow an earlier run's artifact to make a failed launch look successful.
        decompiled.unlink(missing_ok=True)
        env = dict(os.environ)
        env["AETHER_GHIDRA_OUT"] = str(decompiled)
        raw_max_functions = os.environ.get("AETHER_GHIDRA_MAX_FUNCTIONS", "")
        try:
            max_functions = int(raw_max_functions)
        except (TypeError, ValueError):
            max_functions = DEFAULT_MAX_FUNCTIONS
        if max_functions <= 0:
            max_functions = DEFAULT_MAX_FUNCTIONS
        max_functions = min(max_functions, MAX_FUNCTIONS_LIMIT)
        env["AETHER_GHIDRA_MAX_FUNCTIONS"] = str(max_functions)
        env["JAVA_HOME"] = str(self.java_home)
        env["GHIDRA_INSTALL_DIR"] = str(self.ghidra_home)
        env["GHIDRA_HOME"] = str(self.ghidra_home)
        env["GHIDRA_JAVA_HOME"] = str(self.java_home)
        env["PATH"] = str(self.java_home / "bin") + os.pathsep + env.get("PATH", "")
        for name in (
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "JAVA_OPTIONS",
            "GHIDRA_JAVA_OPTIONS",
            "GHIDRA_HEADLESS_JAVA_OPTIONS",
            "CLASSPATH",
        ):
            env.pop(name, None)
        cmd = [
            str(java),
            "-Djava.system.class.loader=ghidra.GhidraClassLoader",
            "-Dfile.encoding=UTF8",
            "-Duser.country=US",
            "-Duser.language=en",
            "-Duser.variant=",
            "-Dsun.java2d.opengl=false",
            "-Dsun.java2d.d3d=false",
            "-Djdk.tls.client.protocols=TLSv1.2,TLSv1.3",
            "-Dpython.console.encoding=UTF-8",
            "-Dlog4j.skipJansi=true",
            "-Xshare:off",
            "-Djavax.xml.accessExternalDTD=",
            "-Djavax.xml.accessExternalSchema=",
            "-Djavax.xml.accessExternalStylesheet=",
            "--enable-native-access=ALL-UNNAMED",
            "-Xmx2G",
            "-XX:ParallelGCThreads=2",
            "-XX:CICompilerCount=2",
            "-Dcpu.core.limit=2",
            f"-Duser.home={isolated_dirs['home']}",
            f"-Dapplication.settingsdir={isolated_dirs['settings']}",
            f"-Dapplication.cachedir={isolated_dirs['cache']}",
            f"-Dapplication.tempdir={isolated_dirs['tmp']}",
            f"-Djava.io.tmpdir={isolated_dirs['tmp']}",
            "-cp",
            str(utility_jar),
            "ghidra.Ghidra",
            "ghidra.app.util.headless.AnalyzeHeadless",
            str(project_dir),
            "AetherRE",
            "-import",
            str(target),
            "-scriptPath",
            str(out_dir),
            "-postScript",
            script.name,
            "-deleteProject",
        ]
        try:
            proc = run_bounded(
                cmd,
                timeout=timeout_from_env("AETHER_GHIDRA_TIMEOUT", 600.0),
                memory_limit_mb=memory_limit_from_env("AETHER_GHIDRA_MEMORY_MB", default=8192),
                cpu_time_limit_s=cpu_limit_from_env("AETHER_GHIDRA_CPU_SECONDS"),
                env=env,
                cwd=str(out_dir),
                shell=False,
            )
            partial_file_exists = decompiled.is_file() and decompiled.stat().st_size > 0
            summary_match = re.search(
                r"AETHER_GHIDRA_SUMMARY\s+attempted=(\d+)\s+succeeded=(\d+)\s+failed=(\d+)\s+truncated=(true|false)\s+limit=(\d+)",
                proc.get("stdout", ""),
            )
            attempted = int(summary_match.group(1)) if summary_match else None
            exported = int(summary_match.group(2)) if summary_match else None
            failed = int(summary_match.group(3)) if summary_match else None
            truncated = summary_match.group(4) == "true" if summary_match else None
            produced_evidence = (
                proc["returncode"] == 0
                and not proc["timed_out"]
                and partial_file_exists
                and summary_match is not None
            )
            complete = produced_evidence and failed == 0 and truncated is False
            exported_match = re.search(r"Exported\s+(\d+)\s+functions", proc.get("stdout", ""))
            result = {
                "ok": proc["returncode"] == 0 and not proc["timed_out"],
                "executed": True,
                "produced_evidence": produced_evidence,
                "partial": proc["returncode"] != 0 or proc["timed_out"] or proc.get("resource_exceeded", False) or not complete,
                "launcher_mode": "direct-java-no-shell",
                "extraction_status": (
                    "complete" if complete else "truncated" if truncated is True else "partial"
                ),
                "max_functions": max_functions,
                "attempted_functions": attempted,
                "exported_functions": exported if exported is not None else (int(exported_match.group(1)) if exported_match else None),
                "failed_functions": failed,
                "truncated": truncated,
                "returncode": proc["returncode"],
                "timed_out": proc["timed_out"],
                "resource_exceeded": proc.get("resource_exceeded", False),
                "resource_kind": proc.get("resource_kind"),
                "stdout_tail": proc["stdout"][-2000:],
                "stderr_tail": proc["stderr"][-2000:],
                "partial_decompiled_path": str(decompiled) if partial_file_exists and not produced_evidence else None,
            }
            if produced_evidence:
                result["decompiled_path"] = str(decompiled)
            return result
        except Exception as e:
            return {
                "ok": False,
                "executed": True,
                "produced_evidence": False,
                "error": str(e),
            }
