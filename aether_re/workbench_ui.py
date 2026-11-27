"""Offline Self-Contained Interactive Forensic & Reverse-Engineering Workbench (v20.0).

Generates a single zero-CDN HTML workbench (`aether_workbench.html`) with 6
searchable, interactive panels:
1. Summary & Custody SHA-512 / HMAC Attestation
2. Decompiler (C/C#/JS) + Callgraph / CFG Blocks
3. 1-Day Binary Diff & SARIF 2.1.0 Findings
4. DFIR Supertimeline with Source & MITRE ATT&CK Tactic Filter
5. DFIR RAM / Containers / TLS Decrypted Traffic
6. CEGIS Differential Parity Certificate (Native DLL & CLI Process)
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _safe_json_for_script(payload: Any) -> str:
    """Serialize JSON safely for inert `<script type='application/json'>` embedding."""
    raw = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    return raw.replace("</", "<\\/")


def generate_workbench_html(
    report_bundle: dict[str, Any],
    output_html_path: str | Path,
    *,
    title: str = "AetherRE Megazord v20.0 — Field-Reality Workbench",
) -> dict[str, Any]:
    """Render a self-contained offline interactive HTML workbench from RE/DFIR/CEGIS reports."""
    out_p = Path(output_html_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)
    safe_title = html.escape(title)
    data_json = _safe_json_for_script(report_bundle)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{safe_title}</title>
<style>
  :root {{ --bg:#0d1117; --card:#161b22; --fg:#e6edf3; --muted:#8b949e; --acc:#58a6ff; --ok:#3fb950; --warn:#d29922; --bad:#f85149; --bd:#30363d; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--fg); }}
  header {{ padding:16px 24px; border-bottom:1px solid var(--bd); display:flex; justify-content:space-between; align-items:center; background:#090d13; }}
  header h1 {{ margin:0; font-size:18px; color:var(--acc); }}
  nav {{ display:flex; gap:8px; padding:12px 24px; border-bottom:1px solid var(--bd); flex-wrap:wrap; background:var(--card); }}
  nav button {{ background:#21262d; color:var(--fg); border:1px solid var(--bd); border-radius:6px; padding:8px 14px; cursor:pointer; font-size:13px; }}
  nav button.active {{ background:var(--acc); color:#0d1117; font-weight:600; border-color:var(--acc); }}
  main {{ padding:20px 24px; max-width:1400px; margin:0 auto; }}
  .panel {{ display:none; }}
  .panel.active {{ display:block; }}
  .card {{ background:var(--card); border:1px solid var(--bd); border-radius:8px; padding:16px; margin-bottom:16px; }}
  .toolbar {{ display:flex; gap:10px; margin-bottom:12px; flex-wrap:wrap; }}
  input, select {{ background:#0d1117; color:var(--fg); border:1px solid var(--bd); border-radius:6px; padding:7px 10px; font-size:13px; }}
  pre {{ background:#0d1117; border:1px solid var(--bd); border-radius:6px; padding:12px; overflow:auto; max-height:460px; font-size:12px; line-height:1.45; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ border-bottom:1px solid var(--bd); padding:8px 10px; text-align:left; }}
  th {{ color:var(--muted); font-weight:600; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:600; background:#21262d; }}
  .ok {{ color:var(--ok); border:1px solid var(--ok); }}
</style>
</head>
<body>
<header>
  <h1>{safe_title}</h1>
  <span class="badge ok">OFFLINE ZERO-CDN • VERDADE RADICAL</span>
</header>
<nav id="tabs">
  <button class="active" data-tab="custody">1. Custody & Summary</button>
  <button data-tab="decomp">2. Decompiler & CFG</button>
  <button data-tab="diff">3. Binary Diff & SARIF</button>
  <button data-tab="timeline">4. Supertimeline MITRE</button>
  <button data-tab="dfir">5. DFIR RAM / Containers / TLS</button>
  <button data-tab="cegis">6. CEGIS Parity Certificate</button>
</nav>
<main>
  <section id="panel-custody" class="panel active"><div class="card"><h3>Custody & Summary</h3><pre id="out-custody"></pre></div></section>
  <section id="panel-decomp" class="panel"><div class="card"><h3>Decompiled Code & VM CFG</h3><pre id="out-decomp"></pre></div></section>
  <section id="panel-diff" class="panel"><div class="card"><h3>1-Day Diff & SARIF 2.1.0</h3><pre id="out-diff"></pre></div></section>
  <section id="panel-timeline" class="panel">
    <div class="card">
      <h3>Supertimeline & EVTX Events</h3>
      <div class="toolbar">
        <input id="tl-search" placeholder="Filter events (EventID, provider, MITRE)..." />
        <select id="tl-tactic"><option value="">All Tactics</option></select>
      </div>
      <table><thead><tr><th>Timestamp</th><th>Source</th><th>Event / Technique</th><th>Details</th></tr></thead><tbody id="tl-body"></tbody></table>
    </div>
  </section>
  <section id="panel-dfir" class="panel"><div class="card"><h3>DFIR RAM, Containers & TLS 1.3 Decryption</h3><pre id="out-dfir"></pre></div></section>
  <section id="panel-cegis" class="panel"><div class="card"><h3>Differential CEGIS Parity Certificate</h3><pre id="out-cegis"></pre></div></section>
</main>
<script id="aether-workbench-data" type="application/json">{data_json}</script>
<script>
(function() {{
  const data = JSON.parse(document.getElementById("aether-workbench-data").textContent || "{{}}");
  const tabs = document.querySelectorAll("#tabs button");
  tabs.forEach(btn => btn.addEventListener("click", () => {{
    tabs.forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("panel-" + btn.dataset.tab).classList.add("active");
  }}));
  const show = (id, obj) => {{ document.getElementById(id).textContent = JSON.stringify(obj || {{}}, null, 2); }};
  show("out-custody", data.custody || data.summary || {{}});
  show("out-decomp", data.decompiler || data.vm_cfg || {{}});
  show("out-diff", data.diff_sarif || {{}});
  show("out-dfir", data.dfir || {{}});
  show("out-cegis", data.cegis || {{}});

  const events = Array.isArray(data.timeline) ? data.timeline : [];
  const tacticSel = document.getElementById("tl-tactic");
  const tactics = [...new Set(events.map(e => e.mitre_tactic).filter(Boolean))];
  tactics.forEach(t => {{ const o = document.createElement("option"); o.value = t; o.textContent = t; tacticSel.appendChild(o); }});

  const renderTimeline = () => {{
    const q = (document.getElementById("tl-search").value || "").toLowerCase();
    const tac = tacticSel.value;
    const body = document.getElementById("tl-body");
    body.innerHTML = "";
    events.filter(e => (!tac || e.mitre_tactic === tac) && (!q || JSON.stringify(e).toLowerCase().includes(q))).slice(0, 250).forEach(e => {{
      const tr = document.createElement("tr");
      [e.timestamp_utc || "", e.source || e.provider || "", e.mitre_technique || e.event_id || "", e.description || e.details || ""].forEach(txt => {{
        const td = document.createElement("td"); td.textContent = String(txt); tr.appendChild(td);
      }});
      body.appendChild(tr);
    }});
  }};
  document.getElementById("tl-search").addEventListener("input", renderTimeline);
  tacticSel.addEventListener("change", renderTimeline);
  renderTimeline();
}})();
</script>
</body>
</html>
"""
    out_p.write_text(html_doc, encoding="utf-8")
    return {
        "schema": "aether_workbench_ui.v1",
        "html_path": str(out_p),
        "size_bytes": out_p.stat().st_size,
        "panels": 6,
    }
