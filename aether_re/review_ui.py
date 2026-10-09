"""Gerador de revisão forense offline em HTML estático.

O documento é uma projeção de relatórios já materializados. Não carrega
scripts, fontes ou dados remotos e não interpreta conteúdo do alvo como HTML;
o navegador recebe apenas JSON inerte e usa ``textContent`` para renderizar.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


SCHEMA = "forensic-review-html.v1"


_STYLE = """
body{font-family:system-ui,sans-serif;background:#10141b;color:#e8edf3;margin:0;padding:24px}
main{max-width:1200px;margin:auto}h1{margin-top:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
.card{background:#1a2230;border:1px solid #344258;border-radius:8px;padding:14px}.status{font-weight:700}
.ok{color:#65d68a}.warn{color:#ffd166}.bad{color:#ff7676}table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{border-bottom:1px solid #344258;text-align:left;padding:7px;vertical-align:top;white-space:pre-wrap;word-break:break-word}
th{color:#9fb1c7}details{margin:12px 0}.muted{color:#9fb1c7;font-size:.9em}
""".strip()


_SCRIPT = r"""
(() => {
  const data = JSON.parse(document.getElementById('report-data').textContent);
  const root = document.getElementById('content');
  const text = value => value === undefined || value === null ? '' : String(value);
  const cell = (tr, value) => { const td = document.createElement('td'); td.textContent = text(value); tr.appendChild(td); };
  const table = (title, rows, columns) => {
    if (!Array.isArray(rows) || rows.length === 0) return;
    const detail = document.createElement('details'); detail.open = true;
    const summary = document.createElement('summary'); summary.textContent = `${title} (${rows.length})`; detail.appendChild(summary);
    const t = document.createElement('table'); const head = document.createElement('tr');
    columns.forEach(column => cell(head, column)); t.appendChild(head);
    rows.forEach(row => { const tr = document.createElement('tr'); columns.forEach(column => cell(tr, typeof row === 'object' ? row[column] : row)); t.appendChild(tr); });
    detail.appendChild(t); root.appendChild(detail);
  };
  const status = text(data.status || 'unknown');
  document.getElementById('status').textContent = status;
  document.getElementById('status').className = `status ${status === 'complete' || status === 'pass' || status === 'verified' ? 'ok' : status === 'partial' || status === 'inconclusive' ? 'warn' : 'bad'}`;
  document.getElementById('schema').textContent = text(data.schema);
  document.getElementById('limitations').textContent = Array.isArray(data.limitations) ? data.limitations.join('\n') : text(data.limitations);
  table('Findings', data.findings, ['engine','severity','title','detail','source','line']);
  table('Indicators', data.indicators, ['rule','severity','reason','state','reachable','source','line']);
  table('Proposals', data.proposals, ['proposal_id','status','hypothesis','evidence_ids','review_required','auto_confirmed']);
  table('Mismatches', data.mismatches, ['kind','reproduction_id','input_sha256','fields']);
  table('Events', data.events, ['seq','timestamp_ns','event','module','function_hint','address_hint','status']);
  table('Evidence', data.evidence, ['evidence_id','run_id','producer','method','validation_status','supports']);
  const summary = document.getElementById('summary'); summary.textContent = JSON.stringify(data.summary || {}, null, 2);
})();
""".strip()


def _safe_json(value: Any) -> str:
    # Escape characters that can terminate a script element; this is data
    # serialization, not an attempt to sanitize/execute target content.
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, default=str)
    return encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def render_review_html(report: dict[str, Any], *, title: str = "AetherRE Forensic Review") -> str:
    """Render one report without external resources or executable report text."""
    if not isinstance(report, dict):
        report = {"schema": SCHEMA, "status": "invalid", "errors": [{"code": "report_must_be_object"}]}
    title_text = html.escape(title if isinstance(title, str) and title.strip() else "AetherRE Forensic Review", quote=True)
    payload = _safe_json(report)
    return f"<!doctype html>\n<html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title_text}</title><style>{_STYLE}</style></head><body><main><h1>{title_text}</h1><div class=\"grid\"><div class=\"card\"><div class=\"muted\">Status</div><div id=\"status\" class=\"status\"></div></div><div class=\"card\"><div class=\"muted\">Schema</div><div id=\"schema\"></div></div><div class=\"card\"><div class=\"muted\">Summary</div><pre id=\"summary\"></pre></div></div><details open><summary>Limitações</summary><pre id=\"limitations\"></pre></details><section id=\"content\"></section></main><script type=\"application/json\" id=\"report-data\">{payload}</script><script>{_SCRIPT}</script></body></html>\n"


def write_review_html(report: dict[str, Any], path: Path, *, title: str = "AetherRE Forensic Review") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_review_html(report, title=title), encoding="utf-8", newline="\n")
