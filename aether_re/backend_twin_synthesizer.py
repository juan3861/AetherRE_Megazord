"""Backend Behavioral Twin Synthesizer for Cloud/SaaS Client Isolation (v14.0).

Synthesizes a standalone runnable local Python HTTP/REST stateful mock server
(`backend_twin_server.py`) and `OPENAPI_INFERRED.json` from:
1. PCAP HTTP events & reassembled TCP streams (`pcap_forensics`).
2. Extracted client endpoint URIs & JSON schema fields.

Enables offline execution of cloned clients whose original cloud backend is
not present on disk.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any


def synthesize_backend_twin(
    *,
    pcap_report: dict[str, Any] | None = None,
    endpoints: list[dict[str, Any]] | None = None,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Synthesize OpenAPI spec and runnable local HTTP server matching observed backend contracts."""
    routes: dict[tuple[str, str], dict[str, Any]] = {}

    if pcap_report:
        for ev in pcap_report.get("http_events", []):
            method = str(ev.get("method") or "GET").upper()
            uri = str(ev.get("uri") or "/")
            key = (method, uri)
            routes[key] = {
                "method": method,
                "path": uri,
                "host": ev.get("host", "localhost"),
                "response_status": 200,
                "response_body": {"status": "ok", "twin_route": uri, "method": method},
            }
        # Inspect TCP streams for JSON HTTP responses
        for st in pcap_report.get("tcp_streams", []):
            prev = str(st.get("preview") or "")
            m_req = re.search(r"(GET|POST|PUT|DELETE|PATCH)\s+(/\S*)\s+HTTP/1\.", prev)
            if m_req:
                k = (m_req.group(1), m_req.group(2))
                routes.setdefault(k, {
                    "method": k[0],
                    "path": k[1],
                    "host": st.get("dst", "localhost"),
                    "response_status": 200,
                    "response_body": {"status": "ok", "twin_route": k[1], "method": k[0]},
                })

    for ep in endpoints or []:
        method = str(ep.get("method") or "GET").upper()
        path = str(ep.get("path") or "/")
        routes[(method, path)] = {
            "method": method,
            "path": path,
            "host": ep.get("host", "localhost"),
            "response_status": int(ep.get("response_status", 200)),
            "response_body": ep.get("response_body") if ep.get("response_body") is not None else {"status": "ok", "twin_route": path},
        }

    if not routes:
        routes[("GET", "/health")] = {
            "method": "GET",
            "path": "/health",
            "host": "localhost",
            "response_status": 200,
            "response_body": {"status": "ok", "twin": "default"},
        }

    paths_openapi: dict[str, Any] = {}
    dispatch_table: dict[str, Any] = {}
    for (method, path), meta in sorted(routes.items()):
        paths_openapi.setdefault(path, {})[method.lower()] = {
            "summary": f"Inferred behavioral twin endpoint for {method} {path}",
            "responses": {
                str(meta["response_status"]): {
                    "description": "Synthesized twin response",
                    "content": {"application/json": {"example": meta["response_body"]}},
                }
            },
        }
        dispatch_table[f"{method} {path}"] = {
            "status": meta["response_status"],
            "body": meta["response_body"],
        }

    openapi = {
        "openapi": "3.0.3",
        "info": {"title": "AetherRE Behavioral Backend Twin", "version": "14.0.0"},
        "paths": paths_openapi,
    }

    server_py = "\n".join([
        "\"\"\"Auto-Synthesized Behavioral Backend Twin Server (AetherRE v14.0).\"\"\"",
        "from __future__ import annotations",
        "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer",
        "import json",
        "import sys",
        "",
        f"ROUTES = json.loads({json.dumps(json.dumps(dispatch_table))})",
        "STATE = {'requests': 0}",
        "",
        "class TwinHandler(BaseHTTPRequestHandler):",
        "    def _handle(self, method: str) -> None:",
        "        STATE['requests'] += 1",
        "        path = self.path.split('?', 1)[0]",
        "        spec = ROUTES.get(f'{method} {path}')",
        "        if spec is None:",
        "            body = json.dumps({'error': 'not_found', 'path': path}).encode('utf-8')",
        "            self.send_response(404)",
        "        else:",
        "            payload = dict(spec['body']) if isinstance(spec['body'], dict) else spec['body']",
        "            if isinstance(payload, dict):",
        "                payload['_request_seq'] = STATE['requests']",
        "            body = json.dumps(payload).encode('utf-8')",
        "            self.send_response(int(spec['status']))",
        "        self.send_header('Content-Type', 'application/json')",
        "        self.send_header('Content-Length', str(len(body)))",
        "        self.end_headers()",
        "        self.wfile.write(body)",
        "    def do_GET(self): self._handle('GET')",
        "    def do_POST(self): self._handle('POST')",
        "    def do_PUT(self): self._handle('PUT')",
        "    def do_DELETE(self): self._handle('DELETE')",
        "    def log_message(self, fmt, *args): pass",
        "",
        "def start_twin_server(host: str = '127.0.0.1', port: int = 0) -> ThreadingHTTPServer:",
        "    return ThreadingHTTPServer((host, port), TwinHandler)",
        "",
        "if __name__ == '__main__':",
        "    srv = start_twin_server('127.0.0.1', int(sys.argv[1]) if len(sys.argv) > 1 else 8080)",
        "    print(f'TWIN_LISTENING:{srv.server_port}', flush=True)",
        "    srv.serve_forever()",
        "",
    ])

    files_written: dict[str, str] = {}
    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        oa_path = out / "OPENAPI_INFERRED.json"
        sv_path = out / "backend_twin_server.py"
        oa_path.write_text(json.dumps(openapi, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        sv_path.write_text(server_py, encoding="utf-8")
        files_written = {"openapi": str(oa_path), "server_py": str(sv_path)}

    return {
        "schema": "aether_backend_twin.v1",
        "routes_count": len(routes),
        "routes": list(dispatch_table.keys()),
        "openapi": openapi,
        "server_py": server_py,
        "files_written": files_written,
    }
