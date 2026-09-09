"""Adapter Ghidra headless — decompilação real quando Ghidra estiver instalado."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

DEFAULT_JDK21 = r"C:\Program Files\Android\Android Studio\jbr"

from aether_re.adapters.base import Adapter


class GhidraAdapter(Adapter):
    name = "ghidra"

    def __init__(self, ghidra_home: str | None = None) -> None:
        self.ghidra_home = Path(
            ghidra_home
            or os.environ.get("GHIDRA_HOME", "")
            or r"D:\AetherRE_Megazord\tools\ghidra_12.1.2_PUBLIC"
        )

    def _analyze_headless(self) -> Path | None:
        if not self.ghidra_home.exists():
            return None
        # support both install layouts
        candidates = list(self.ghidra_home.rglob("analyzeHeadless.bat"))
        candidates += list(self.ghidra_home.rglob("analyzeHeadless"))
        return candidates[0] if candidates else None

    def available(self) -> bool:
        return self._analyze_headless() is not None

    def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
        tool = self._analyze_headless()
        if not tool:
            return {
                "ok": False,
                "error": "Ghidra não instalado. Defina GHIDRA_HOME ou corra install_tools.ps1",
            }

        project_dir = out_dir / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)
        export_dir = out_dir / "ghidra_export"
        export_dir.mkdir(parents=True, exist_ok=True)

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
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        FileWriter fw = new FileWriter(outPath);
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int n = 0;
        while (it.hasNext() && n < 200) {
            Function f = it.next();
            DecompileResults res = ifc.decompileFunction(f, 30, monitor);
            if (res != null && res.decompileCompleted()) {
                fw.write("/* " + f.getName() + " @ " + f.getEntryPoint() + " */\\n");
                fw.write(res.getDecompiledFunction().getC());
                fw.write("\\n\\n");
                n++;
            }
        }
        fw.close();
        println("Exported " + n + " functions");
    }
}
""".strip(),
            encoding="utf-8",
        )

        decompiled = export_dir / "decompiled.c"
        env = dict(os.environ)
        env["AETHER_GHIDRA_OUT"] = str(decompiled)
        env["JAVA_HOME"] = DEFAULT_JDK21
        env["PATH"] = str(Path(DEFAULT_JDK21) / "bin") + os.pathsep + env.get("PATH", "")

        cmd = [
            str(tool),
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
        env["GHIDRA_INSTALL_DIR"] = str(self.ghidra_home)
        env.pop("JAVA_TOOL_OPTIONS", None)
        env.pop("JDK_HOME", None)
        env.pop("JRE_HOME", None)
        env.pop("ANTIGRAVITY_JAVA_HOME", None)
        env.pop("JAVA_HOME", None)
        env["JAVA_HOME"] = DEFAULT_JDK21
        env["GHIDRA_HOME"] = str(self.ghidra_home)
        env["GHIDRA_JAVA_HOME"] = DEFAULT_JDK21
        env["_JAVA_OPTIONS"] = ""
        env["JDK_JAVA_OPTIONS"] = ""
        env["JAVA_OPTIONS"] = ""
        env["GHIDRA_USE_OWN_JAVA"] = "true"
        env["GHIDRA_ASK_JAVA_HOME"] = "false"
        env["GHIDRA_QUIET"] = "true"
        env["GHIDRA_BATCH"] = "true"
        env["GHIDRA_HEADLESS"] = "true"
        env["JAVA_HOME_OVERRIDE"] = DEFAULT_JDK21
        env["GHIDRA_FORCE_JAVA_HOME"] = DEFAULT_JDK21
        env["JAVA_EXE"] = str(Path(DEFAULT_JDK21) / "bin" / "java.exe")
        env["JAVAC_EXE"] = str(Path(DEFAULT_JDK21) / "bin" / "javac.exe")
        env["JAVAW_EXE"] = str(Path(DEFAULT_JDK21) / "bin" / "javaw.exe")
        env["PATH"] = str(Path(DEFAULT_JDK21) / "bin") + os.pathsep + env.get("PATH", "")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                env=env,
                cwd=str(out_dir),
            )
            return {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout_tail": (proc.stdout or "")[-2000:],
                "stderr_tail": (proc.stderr or "")[-2000:],
                "decompiled_path": str(decompiled) if decompiled.exists() else None,
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}
