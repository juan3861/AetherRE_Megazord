"""Adapter Frida — análise dinâmica (hooks em runtime)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from aether_re.adapters.base import Adapter


class FridaAdapter(Adapter):
    name = "frida"

    def available(self) -> bool:
        return (
            importlib.util.find_spec("frida") is not None
            or shutil.which("frida") is not None
            or shutil.which("frida-ps") is not None
        )

    def capture_live_frida_trace(
        self,
        target: Path,
        out_dir: Path,
        *,
        timeout_s: float = 4.0,
        args: list[str] | None = None,
        hook_apis: list[str] | None = None,
    ) -> dict[str, Any]:
        """Spawn a controlled target under live Python `frida` in an isolated bounded worker subprocess."""
        if importlib.util.find_spec("frida") is None:
            return {"ok": False, "executed": False, "error": "Python frida module not installed"}

        target_p = Path(target).resolve()
        if not target_p.is_file():
            raise FileNotFoundError(f"Target not found: {target_p}")
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        trace_path = out_dir / "frida_live_trace.json"

        apis = hook_apis or [
            "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
            "CreateFileW", "CreateProcessW", "GetProcAddress", "ExitProcess",
        ]
        bounded_t = min(max(float(timeout_s), 0.3), 10.0)
        cfg = {
            "target": str(target_p),
            "argv": [str(target_p), *(args or [])],
            "apis": apis,
            "timeout_s": bounded_t,
            "trace_path": str(trace_path),
        }
        worker_src = r"""
import json, sys, time, frida
cfg = json.loads(sys.stdin.read())
events, modules = [], []
js_code = f'''
const interesting = {json.dumps(cfg['apis'])};
const mods = Process.enumerateModules().slice(0, 64).map(m => ({{name: m.name, base: m.base.toString(), size: m.size}}));
send({{kind: 'modules', modules: mods}});
for (const api of interesting) {{
    const addr = Module.findGlobalExportByName ? Module.findGlobalExportByName(api) : Module.findExportByName(null, api);
    if (!addr) continue;
    try {{
        Interceptor.attach(addr, {{
            onEnter(args) {{
                send({{kind: 'api_hit', api: api, arg0: args[0] ? args[0].toString() : '0', arg1: args[1] ? args[1].toString() : '0'}});
            }}
        }});
    }} catch (e) {{}}
}}
'''
dev = frida.get_local_device()
pid = None
session = None
try:
    pid = dev.spawn(cfg['argv'], cwd=sys.path[0] if False else __import__('pathlib').Path(cfg['target']).parent.as_posix())
    session = dev.attach(pid)
    script = session.create_script(js_code)
    def _on_msg(msg, _data):
        if msg.get('type') == 'send':
            pl = msg.get('payload') or {}
            if pl.get('kind') == 'modules':
                modules.extend(pl.get('modules', []))
            elif pl.get('kind') == 'api_hit':
                events.append(pl)
    script.on('message', _on_msg)
    script.load()
    dev.resume(pid)
    time.sleep(cfg['timeout_s'])
finally:
    if session is not None:
        try: session.detach()
        except Exception: pass
    if pid is not None:
        try: dev.kill(pid)
        except Exception: pass
rep = {
    'schema': 'aether_frida_live_trace.v1',
    'ok': True,
    'executed': True,
    'produced_evidence': True,
    'mode': 'live_frida_spawn',
    'frida_version': getattr(frida, '__version__', 'unknown'),
    'target': cfg['target'],
    'modules_count': len(modules),
    'events_count': len(events),
    'modules': modules[:64],
    'events': events[:256],
    'trace_path': cfg['trace_path'],
}
__import__('pathlib').Path(cfg['trace_path']).write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding='utf-8')
print('FRIDA_OK')
"""
        proc = subprocess.run(
            [sys.executable, "-c", worker_src],
            input=json.dumps(cfg),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=bounded_t + 15.0,
        )
        if proc.returncode != 0 or not trace_path.is_file():
            raise RuntimeError(f"Frida worker failed rc={proc.returncode}: {(proc.stdout + proc.stderr)[:400]}")
        return json.loads(trace_path.read_text(encoding="utf-8"))

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
            "available": True,
            "executed": True,
            "produced_evidence": False,
            "partial": True,
            "mode": "script_generated",
            "script": str(script),
            "guide": str(guide),
            "note": "Dinâmico não auto-executa o alvo (segurança); nenhum trace foi coletado nesta execução.",
        }
