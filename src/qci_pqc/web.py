"""Local web UI for QCI PQC scanner. Stdlib only. Binds to 127.0.0.1."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from . import __version__
from .adapters import get_adapter
from .dedupe import deduplicate
from .enrich import enrich_findings
from .models import Inventory
from .report import write_reports
from .scoring import compute_readiness, score_scanner
from .scoresplit import split_scores

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>QCI PQC Scanner</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #f4f6f8; }}
.card {{ max-width: 720px; margin: auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.08); }}
h1 {{ margin-top: 0; }}
label {{ display: block; margin: 1rem 0 .3rem; font-weight: 600; }}
input, select {{ width: 100%; padding: .5rem; box-sizing: border-box; }}
button {{ margin-top: 1.2rem; padding: .6rem 1.2rem; background: #1a1a2e; color: white; border: 0; border-radius: 4px; cursor: pointer; }}
.note {{ color: #555; font-size: .9rem; }}
</style>
</head>
<body>
<div class="card">
  <h1>QCI PQC Readiness Scanner</h1>
  <p class="note">Local UI · v{version} · same engine as the CLI</p>
  <form method="post" action="/scan">
    <label>Path to scan</label>
    <input name="path" required placeholder="/path/to/repo">
    <label>Adapter</label>
    <select name="adapter">
      <option value="internal">internal</option>
      <option value="semgrep">semgrep</option>
      <option value="internal,semgrep">internal + semgrep</option>
    </select>
    <button type="submit">Run scan</button>
  </form>
  <p class="note">Results are written under <code>./qci-pqc-web-out</code> and shown in the browser. CLI remains available: <code>qci-pqc scan …</code></p>
</div>
</body>
</html>
"""


def run_scan(path: Path, adapter: str, out: Path) -> Inventory:
    adapters = [a.strip() for a in adapter.split(",") if a.strip()]
    findings = []
    used = []
    for name in adapters:
        scanner = get_adapter(name)
        if not scanner.available():
            continue
        findings.extend(scanner.scan(path))
        used.append(scanner.name)
    if not findings:
        scanner = get_adapter("internal")
        findings = scanner.scan(path)
        used = [scanner.name]
    findings = deduplicate(findings)
    findings = enrich_findings(findings)
    inv = Inventory(project=path.name, scanners_used=used, findings=findings)
    inv.coverage = score_scanner(findings)
    inv.readiness_score, inv.priority_findings, inv.readiness_breakdown = compute_readiness(findings)
    out.mkdir(parents=True, exist_ok=True)
    write_reports(inv, out)
    return inv


def make_handler(out_dir: Path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _send(self, code: int, body: bytes, content_type: str = "text/html; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, PAGE.format(version=__version__).encode())
                return
            if self.path.startswith("/report"):
                report = out_dir / "report.html"
                if report.exists():
                    self._send(200, report.read_bytes())
                else:
                    self._send(404, b"No report yet. Run a scan.")
                return
            self._send(404, b"Not found")

        def do_POST(self):
            if self.path != "/scan":
                self._send(404, b"Not found")
                return
            length = int(self.headers.get("Content-Length", 0))
            data = parse_qs(self.rfile.read(length).decode())
            raw_path = (data.get("path") or [""])[0].strip()
            adapter = (data.get("adapter") or ["internal"])[0]
            target = Path(raw_path)
            if not target.is_dir():
                self._send(400, f"<p>Not a directory: {raw_path}</p><p><a href='/'>Back</a></p>".encode())
                return
            try:
                inv = run_scan(target, adapter, out_dir)
            except Exception as e:
                self._send(500, f"<p>Scan failed: {e}</p><p><a href='/'>Back</a></p>".encode())
                return
            counts = split_scores(inv.findings)
            body = f"""<!DOCTYPE html><html><body style="font-family:system-ui;margin:2rem">
            <h1>Scan complete</h1>
            <p>Project: <strong>{inv.project}</strong></p>
            <p>Source findings: <strong>{counts['source']['count']}</strong></p>
            <p>Artifact findings: <strong>{counts['artifact']['count']}</strong></p>
            <p>Not blended: <strong>{len(inv.findings)}</strong></p>
            <p>Readiness: <strong>{inv.readiness_score}</strong> / 100</p>
            <p><a href="/report">Open full report</a></p>
            <p><a href="/">New scan</a></p>
            </body></html>"""
            self._send(200, body.encode())

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8080, out: str = "qci-pqc-web-out"):
    out_dir = Path(out).resolve()
    server = ThreadingHTTPServer((host, port), make_handler(out_dir))
    print(f"QCI PQC web UI at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
