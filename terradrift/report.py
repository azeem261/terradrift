from __future__ import annotations

import html
from datetime import datetime, timezone

from .findings import DriftFinding

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def print_console_report(findings: list[DriftFinding]) -> None:
    print()
    print("=" * 72)
    print("  TERRADRIFT")
    print("=" * 72)
    print(f"  Drift findings  : {len(findings)}")
    if not findings:
        print("  Nothing drifted — live AWS state matches Terraform state.")
        print("=" * 72)
        return

    by_sev = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    print(f"  High: {by_sev['high']}   Medium: {by_sev['medium']}   Low: {by_sev['low']}")
    print("=" * 72)

    for f in sorted(findings, key=lambda x: _SEVERITY_ORDER.get(x.severity, 9)):
        print(f"\n  [{f.severity.upper()}] {f.resource_address}  ({f.resource_type})")
        print(f"    live id  : {f.live_id}")
        print(f"    field    : {f.field}")
        print(f"    expected : {f.expected}")
        print(f"    actual   : {f.actual}")
        if f.details.get("note"):
            print(f"    note     : {f.details['note']}")
    print()


def write_html_report(findings: list[DriftFinding], path: str) -> None:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    by_sev = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    rows = []
    for f in sorted(findings, key=lambda x: _SEVERITY_ORDER.get(x.severity, 9)):
        rows.append(
            "<tr>"
            f'<td><span class="sev sev-{html.escape(f.severity)}">{html.escape(f.severity)}</span></td>'
            f'<td class="mono">{html.escape(f.resource_address)}</td>'
            f'<td class="mono">{html.escape(f.resource_type)}</td>'
            f"<td>{html.escape(str(f.field))}</td>"
            f'<td class="mono">{html.escape(str(f.expected))}</td>'
            f'<td class="mono">{html.escape(str(f.actual))}</td>'
            "</tr>"
        )
    findings_html = "\n".join(rows) if rows else (
        '<tr><td colspan="6" class="muted" style="padding:24px;">No drift found — live AWS state matches Terraform state.</td></tr>'
    )

    page = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>Terradrift Report</title>
<style>
  body {{ background:#0a0e12; color:#e7edf2; font-family: -apple-system, 'Helvetica Neue', Arial, sans-serif; margin:0; padding:40px 32px 64px; }}
  .wrap {{ max-width: 1080px; margin: 0 auto; }}
  h1 {{ font-size: 1.9rem; margin: 0 0 6px; }}
  .meta {{ color:#8b96a3; font-family: Menlo, Consolas, monospace; font-size: 0.85rem; margin-bottom: 28px; }}
  .totals {{ display:flex; gap:14px; margin-bottom: 32px; flex-wrap: wrap; }}
  .tile {{ background:#11161c; border:1px solid #26303a; border-radius:4px; padding:16px 20px; min-width: 140px; }}
  .tile .label {{ font-family: Menlo, Consolas, monospace; font-size:0.72rem; letter-spacing:0.08em; text-transform:uppercase; color:#6d7f8f; }}
  .tile .value {{ font-family: Menlo, Consolas, monospace; font-size:1.6rem; font-weight:600; margin-top:6px; }}
  .tile.high .value {{ color:#f2545a; }}
  .tile.medium .value {{ color:#f2a541; }}
  .tile.low .value {{ color:#4fd8c4; }}
  table {{ width:100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align:left; font-family: Menlo, Consolas, monospace; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.06em; color:#6d7f8f; padding: 10px 12px; border-bottom: 1px solid #26303a; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1a2129; vertical-align: top; }}
  .mono {{ font-family: Menlo, Consolas, monospace; font-size:0.8rem; }}
  .muted {{ color:#8b96a3; }}
  .sev {{ font-family: Menlo, Consolas, monospace; font-size:0.72rem; text-transform:uppercase; padding:2px 8px; border-radius:3px; }}
  .sev-high {{ background: rgba(242,84,90,0.15); color:#f2545a; }}
  .sev-medium {{ background: rgba(242,165,65,0.15); color:#f2a541; }}
  .sev-low {{ background: rgba(79,216,196,0.15); color:#4fd8c4; }}
  footer {{ margin-top: 40px; color:#55636f; font-size:0.78rem; font-family: Menlo, Consolas, monospace; }}
</style></head>
<body><div class="wrap">
  <h1>Terradrift Report</h1>
  <div class="meta">generated {html.escape(generated_at)}</div>

  <div class="totals">
    <div class="tile"><div class="label">Findings</div><div class="value">{len(findings)}</div></div>
    <div class="tile high"><div class="label">High</div><div class="value">{by_sev['high']}</div></div>
    <div class="tile medium"><div class="label">Medium</div><div class="value">{by_sev['medium']}</div></div>
    <div class="tile low"><div class="label">Low</div><div class="value">{by_sev['low']}</div></div>
  </div>

  <table>
    <thead><tr><th>Severity</th><th>Resource</th><th>Type</th><th>Field</th><th>Expected (state)</th><th>Actual (live)</th></tr></thead>
    <tbody>
      {findings_html}
    </tbody>
  </table>

  <footer>terradrift &#8212; compares Terraform state against live AWS. Not affiliated with HashiCorp or driftctl/Snyk.</footer>
</div></body></html>"""

    with open(path, "w") as fh:
        fh.write(page)
