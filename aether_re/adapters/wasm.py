from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

from aether_re.adapters._static_base import doc
from aether_re.adapters.base import Adapter
from aether_re.process import run_bounded
def normalize_wasm(payload:dict,artifact_id:str,evidence_ref:str):
 losses=tuple(['function_names'] if not payload.get('name_section',False) else [])
 return doc('wasm',artifact_id,(evidence_ref,),payload,'wasm',{'functions':'function','imports':'import','exports':'export','custom_sections':'custom_section'},losses)
class WasmAdapter(Adapter):
 name='wasm'
 _DEFAULT = Path(r'E:\AetherRE_Toolchain\packages\wabt-1.0.41\bin\wasm2wat.exe')
 _SHA256 = 'd9390afcdba5ab3721c0ea4593f84e445066d97a5e8689f387e7901d675d319c'

 def __init__(self, executable: str | None = None) -> None:
  self.executable = Path(executable or os.environ.get('AETHER_WABT_BIN', '') or self._DEFAULT)

 def _verified(self) -> bool:
  try:
   return self.executable.is_file() and hashlib.sha256(self.executable.read_bytes()).hexdigest() == self._SHA256
  except OSError:
   return False

 def available(self) -> bool:
  return self._verified()

 @staticmethod
 def _parse_wat(text: str) -> dict[str, Any]:
  imports = re.findall(r'\(import\s+"([^"]+)"\s+"([^"]+)"', text)
  exports = re.findall(r'\(export\s+"([^"]+)"', text)
  function_names = sorted(set(re.findall(r'\(func\s+\$([A-Za-z0-9_.-]+)', text)))
  tokens = re.findall(r'"(?:\\.|[^"\\])*"|[()]|[^\s()]+', text)
  stack: list[dict[str, str | None]] = []
  functions = 0
  for token in tokens:
   if token == '(':
    stack.append({'head': None})
   elif token == ')':
    if stack:
     stack.pop()
   elif stack and stack[-1]['head'] is None and not token.startswith('(;'):
    stack[-1]['head'] = token
    parent = stack[-2]['head'] if len(stack) > 1 else None
    if token == 'func' and parent in {None, 'module'}:
     functions += 1
  return {'functions': functions, 'function_names': function_names, 'imports': [{'module': a, 'name': b} for a, b in imports], 'exports': exports, 'name_section': '$' in text}

 def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
  if not self.available():
   return {'ok': False, 'available': False, 'executed': False, 'produced_evidence': False, 'partial': False, 'error': 'wabt_worker_unavailable_or_hash_mismatch'}
  try:
   raw = target.read_bytes()[:4]
  except OSError:
   return {'ok': False, 'available': True, 'executed': False, 'produced_evidence': False, 'partial': False, 'error': 'wasm_input_unreadable'}
  if raw != b'\0asm':
   return {'ok': False, 'available': True, 'executed': False, 'produced_evidence': False, 'partial': False, 'error': 'wasm_magic_missing'}
  out_dir.mkdir(parents=True, exist_ok=True)
  run = run_bounded([str(self.executable), str(target)], timeout=60.0, memory_limit_mb=512, cpu_time_limit_s=60, cwd=str(out_dir))
  wat = str(run.get('stdout', ''))
  evidence = out_dir / 'module.wat'
  evidence.write_text(wat, encoding='utf-8', newline='\n')
  good = run.get('returncode') == 0 and not run.get('timed_out') and bool(wat.strip())
  return {'ok': good, 'available': True, 'executed': True, 'produced_evidence': good, 'partial': not good,
          'returncode': run.get('returncode'), 'timed_out': run.get('timed_out'), 'functions': self._parse_wat(wat),
          'report': str(evidence), 'stderr_tail': str(run.get('stderr', ''))[-1000:]}
