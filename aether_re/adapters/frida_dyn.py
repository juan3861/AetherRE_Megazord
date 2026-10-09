"""Adapter Frida — análise dinâmica (hooks em runtime)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from aether_re.adapters.base import Adapter


class FridaAdapter(Adapter):
    name = "frida"

    def available(self) -> bool:
        return shutil.which("frida") is not None or shutil.which("frida-ps") is not None

    def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
        if not self.available():
            return {
                "ok": False,
                "available": False,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
                "error": "Frida não instalado (pip install frida-tools)",
                "hint": "Análise dinâmica requer execução controlada do alvo.",
            }

        # Não lançamos o alvo automaticamente (segurança). Geramos script + instruções.
        script = out_dir / "frida_hooks.js"
        script.write_text(
            """
// AetherRE Megazord — hooks Frida (Windows)
// Uso: frida -f PATH_DO_ALVO -l frida_hooks.js --no-pause

const interesting = [
  'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
  'CreateRemoteThread', 'LoadLibraryA', 'LoadLibraryW',
  'GetProcAddress', 'WinExec', 'CreateProcessW'
];

function hookByName(mod, name) {
  const addr = Module.findExportByName(mod, name);
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      console.log('[hit] ' + name + ' @ ' + this.returnAddress);
    }
  });
}

setImmediate(function () {
  const mods = ['kernel32.dll', 'ntdll.dll'];
  for (const m of mods) {
    for (const n of interesting) {
      try { hookByName(m, n); } catch (e) {}
    }
  }
  console.log('[AetherRE] hooks instalados');
});
""".strip(),
            encoding="utf-8",
        )
        guide = out_dir / "frida_HOW_TO.txt"
        guide.write_text(
            f"frida -f \"{target}\" -l \"{script}\" --no-pause\n",
            encoding="utf-8",
        )
        return {
            "ok": True,
            "executed": True,
            "produced_evidence": False,
            "partial": True,
            "mode": "script_generated",
            "script": str(script),
            "guide": str(guide),
            "note": "Dinâmico não auto-executa o alvo (segurança); nenhum trace foi coletado nesta execução.",
        }
