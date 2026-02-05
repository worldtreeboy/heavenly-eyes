"""Report generation for HeavenlyEyes — JSON and elite HTML reports."""

import json
import html as html_lib
from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console

console = Console()


class ReportCollector:
    """Collects findings across modules and generates reports."""

    def __init__(self, target: str):
        self.target = target
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.sections: dict[str, dict] = {}

    def add_section(self, name: str, data: dict):
        self.sections[name] = data

    def to_dict(self) -> dict:
        return {
            "tool": "HeavenlyEyes",
            "version": "2.0.0",
            "target": self.target,
            "timestamp": self.timestamp,
            "findings": self.sections,
        }

    def save_json(self, output_dir: str | None = None) -> Path:
        out = Path(output_dir) if output_dir else Path.cwd() / "heyes_reports"
        out.mkdir(parents=True, exist_ok=True)

        safe_target = self.target.replace("/", "_").replace(":", "_").replace("@", "_at_")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = out / f"heyes_{safe_target}_{ts}.json"

        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

        console.print(f"\n[green]Report saved:[/green] {filepath}")
        return filepath

    def save_html(self, output_dir: str | None = None) -> Path:
        out = Path(output_dir) if output_dir else Path.cwd() / "heyes_reports"
        out.mkdir(parents=True, exist_ok=True)

        safe_target = self.target.replace("/", "_").replace(":", "_").replace("@", "_at_")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = out / f"heyes_{safe_target}_{ts}.html"

        content = self._render_html()
        with open(filepath, "w") as f:
            f.write(content)

        console.print(f"[green]HTML Report saved:[/green] {filepath}")
        return filepath

    # ── Helper: calculate stats ──────────────────────────────────────

    def _calc_stats(self) -> dict:
        total = 0
        categories = {}
        confidences = []

        # Handle pivot_findings format
        pf = self.sections.get("pivot_findings", {})
        if pf and "findings" in pf:
            findings = pf["findings"]
            total = len(findings)
            for f in findings:
                cat = f.get("category", "other")
                categories[cat] = categories.get(cat, 0) + 1
                confidences.append(f.get("confidence", 50))
        else:
            # Legacy format — count all section keys
            for name, data in self.sections.items():
                if isinstance(data, dict):
                    total += len(data)
                    categories[name] = len(data)

        avg_conf = sum(confidences) / len(confidences) if confidences else 0
        high_count = sum(1 for c in confidences if c >= 75)
        risk = min(100, total * 3 + high_count * 5)
        risk_label = "LOW" if risk < 30 else "MEDIUM" if risk < 60 else "HIGH" if risk < 80 else "CRITICAL"
        risk_color = "#10b981" if risk < 30 else "#f59e0b" if risk < 60 else "#ef4444" if risk < 80 else "#dc2626"

        return {
            "total": total,
            "categories": categories,
            "avg_confidence": avg_conf,
            "high_count": high_count,
            "risk": risk,
            "risk_label": risk_label,
            "risk_color": risk_color,
        }

    # ── Render findings rows ─────────────────────────────────────────

    def _render_findings_rows(self) -> str:
        pf = self.sections.get("pivot_findings", {})
        if pf and "findings" in pf:
            rows = ""
            for i, f in enumerate(sorted(pf["findings"], key=lambda x: x.get("confidence", 0), reverse=True), 1):
                conf = f.get("confidence", 50)
                if conf >= 75:
                    badge_class = "badge-high"
                elif conf >= 55:
                    badge_class = "badge-med"
                else:
                    badge_class = "badge-low"

                val = html_lib.escape(str(f.get("value", "")))
                # Auto-link URLs
                if val.startswith("http"):
                    val = f'<a href="{val}" target="_blank">{val}</a>'

                rows += f"""<tr>
                    <td>{i}</td>
                    <td><span class="cat-badge">{html_lib.escape(f.get("category", ""))}</span></td>
                    <td class="finding-label">{html_lib.escape(f.get("label", ""))}</td>
                    <td class="finding-value">{val}</td>
                    <td><span class="conf-badge {badge_class}">{conf}%</span></td>
                    <td class="source">{html_lib.escape(f.get("source", ""))}</td>
                </tr>"""
            return rows

        # Legacy sections
        rows = ""
        i = 0
        for name, data in self.sections.items():
            if not isinstance(data, dict):
                continue
            for key, val in data.items():
                i += 1
                if isinstance(val, (dict, list)):
                    val_str = html_lib.escape(json.dumps(val, default=str)[:200])
                else:
                    val_str = html_lib.escape(str(val))
                rows += f"""<tr>
                    <td>{i}</td>
                    <td><span class="cat-badge">{html_lib.escape(name)}</span></td>
                    <td class="finding-label">{html_lib.escape(key)}</td>
                    <td class="finding-value">{val_str}</td>
                    <td><span class="conf-badge badge-med">—</span></td>
                    <td>—</td>
                </tr>"""
        return rows

    # ── Category cards ───────────────────────────────────────────────

    def _render_category_cards(self, categories: dict) -> str:
        icons = {
            "social_profile": "👤", "email": "📧", "domain": "🌐", "dns": "📡",
            "breach": "💀", "technology": "⚙️", "organization": "🏢",
            "identity": "🪪", "location": "📍", "infrastructure": "🖥️",
            "vulnerability": "🔓", "config_files": "📄", "data_exposure": "⚠️",
        }
        cards = ""
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            icon = icons.get(cat, "📌")
            cards += f"""<div class="stat-card">
                <div class="stat-icon">{icon}</div>
                <div class="stat-value">{count}</div>
                <div class="stat-label">{cat.replace('_', ' ').title()}</div>
            </div>"""
        return cards

    # ── Full HTML render ─────────────────────────────────────────────

    def _render_html(self) -> str:
        s = self._calc_stats()
        findings_rows = self._render_findings_rows()
        category_cards = self._render_category_cards(s["categories"])
        risk_pct = s["risk"]
        risk_deg = int(risk_pct * 1.8)  # 0-180 degrees for gauge

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HeavenlyEyes Report — {html_lib.escape(self.target)}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: 'Inter', 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background: #05050a;
        color: #e2e8f0;
        line-height: 1.6;
    }}

    /* ── Header ── */
    .header {{
        background: linear-gradient(135deg, #0a0a1a 0%, #0f172a 50%, #0a0a1a 100%);
        border-bottom: 1px solid #1e293b;
        padding: 2rem 3rem;
    }}
    .header-inner {{ max-width: 1400px; margin: 0 auto; }}
    .brand {{
        font-size: 1.8rem; font-weight: 800;
        background: linear-gradient(135deg, #06b6d4, #3b82f6);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        letter-spacing: -0.5px;
    }}
    .brand-sub {{ color: #64748b; font-size: 0.85rem; margin-top: 0.25rem; }}
    .target-badge {{
        display: inline-block; margin-top: 1rem;
        background: #0f172a; border: 1px solid #1e293b; border-radius: 8px;
        padding: 0.75rem 1.5rem;
    }}
    .target-badge strong {{ color: #06b6d4; font-size: 1.2rem; }}
    .target-meta {{ color: #64748b; font-size: 0.8rem; margin-top: 0.25rem; }}

    /* ── Main ── */
    .main {{ max-width: 1400px; margin: 0 auto; padding: 2rem 3rem; }}

    /* ── Risk Gauge ── */
    .risk-section {{ display: flex; gap: 2rem; margin-bottom: 2rem; flex-wrap: wrap; }}
    .gauge-card {{
        background: #0f172a; border: 1px solid #1e293b; border-radius: 12px;
        padding: 2rem; text-align: center; min-width: 220px;
    }}
    .gauge {{
        width: 160px; height: 80px; margin: 0 auto 1rem;
        position: relative; overflow: hidden;
    }}
    .gauge-bg {{
        width: 160px; height: 80px;
        border-radius: 80px 80px 0 0;
        background: conic-gradient(from 180deg at 50% 100%, #1e293b 0deg, #1e293b 180deg);
        position: absolute;
    }}
    .gauge-fill {{
        width: 160px; height: 80px;
        border-radius: 80px 80px 0 0;
        background: conic-gradient(from 180deg at 50% 100%, {s['risk_color']} 0deg, {s['risk_color']} {risk_deg}deg, transparent {risk_deg}deg);
        position: absolute;
    }}
    .gauge-center {{
        position: absolute; bottom: 0; left: 50%; transform: translateX(-50%);
        width: 120px; height: 60px; background: #0f172a;
        border-radius: 60px 60px 0 0;
        display: flex; align-items: flex-end; justify-content: center; padding-bottom: 4px;
    }}
    .gauge-value {{ font-size: 1.5rem; font-weight: 800; color: {s['risk_color']}; }}
    .risk-label {{
        font-size: 1.1rem; font-weight: 700; color: {s['risk_color']};
        margin-top: 0.5rem;
    }}

    /* ── Stat Cards ── */
    .stats-grid {{
        display: flex; gap: 1rem; flex-wrap: wrap; flex: 1;
    }}
    .stat-card {{
        background: #0f172a; border: 1px solid #1e293b; border-radius: 10px;
        padding: 1rem 1.25rem; min-width: 130px; flex: 1;
        transition: border-color 0.2s;
    }}
    .stat-card:hover {{ border-color: #06b6d4; }}
    .stat-icon {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
    .stat-value {{ font-size: 1.5rem; font-weight: 800; color: #f1f5f9; }}
    .stat-label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }}

    /* ── Summary Cards ── */
    .summary-row {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
    .summary-card {{
        background: #0f172a; border: 1px solid #1e293b; border-radius: 10px;
        padding: 1.25rem; flex: 1; min-width: 200px;
    }}
    .summary-card h3 {{ color: #06b6d4; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 0.5rem; }}
    .summary-card .big {{ font-size: 2rem; font-weight: 800; color: #f1f5f9; }}

    /* ── Findings Table ── */
    .findings-section {{ margin-top: 2rem; }}
    .findings-section h2 {{
        font-size: 1.3rem; font-weight: 700; color: #f1f5f9;
        margin-bottom: 1rem; padding-bottom: 0.5rem;
        border-bottom: 2px solid #1e293b;
    }}
    .findings-table {{
        width: 100%; border-collapse: separate; border-spacing: 0;
        background: #0f172a; border-radius: 12px; overflow: hidden;
        border: 1px solid #1e293b;
    }}
    .findings-table th {{
        background: #1e293b; color: #94a3b8; font-size: 0.75rem;
        text-transform: uppercase; letter-spacing: 0.5px;
        padding: 0.75rem 1rem; text-align: left; font-weight: 600;
    }}
    .findings-table td {{
        padding: 0.65rem 1rem; border-bottom: 1px solid #1e293b;
        font-size: 0.85rem; vertical-align: middle;
    }}
    .findings-table tr:last-child td {{ border-bottom: none; }}
    .findings-table tr:hover {{ background: #1a2332; }}

    .finding-label {{ font-weight: 600; color: #e2e8f0; }}
    .finding-value {{ color: #94a3b8; word-break: break-all; max-width: 350px; }}
    .finding-value a {{ color: #06b6d4; text-decoration: none; }}
    .finding-value a:hover {{ text-decoration: underline; }}
    .source {{ color: #475569; font-size: 0.8rem; font-style: italic; }}

    /* ── Badges ── */
    .cat-badge {{
        display: inline-block; background: #1e293b; color: #06b6d4;
        padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem;
        font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;
    }}
    .conf-badge {{
        display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
        font-size: 0.75rem; font-weight: 700;
    }}
    .badge-high {{ background: rgba(16, 185, 129, 0.15); color: #10b981; }}
    .badge-med {{ background: rgba(245, 158, 11, 0.15); color: #f59e0b; }}
    .badge-low {{ background: rgba(239, 68, 68, 0.15); color: #ef4444; }}

    /* ── Footer ── */
    .footer {{
        margin-top: 3rem; padding: 2rem 3rem;
        border-top: 1px solid #1e293b;
        text-align: center;
    }}
    .footer-disclaimer {{
        background: #1c1917; border: 1px solid #78350f; border-radius: 8px;
        padding: 1rem 1.5rem; margin-bottom: 1.5rem;
        color: #fbbf24; font-size: 0.8rem;
    }}
    .footer-brand {{ color: #475569; font-size: 0.8rem; }}
    .footer-brand a {{ color: #06b6d4; text-decoration: none; }}

    @media (max-width: 768px) {{
        .header, .main, .footer {{ padding: 1rem; }}
        .risk-section {{ flex-direction: column; }}
    }}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
    <div class="header-inner">
        <div class="brand">HEAVENLY EYES</div>
        <div class="brand-sub">All-seeing OSINT Reconnaissance — Report v2.0</div>
        <div class="target-badge">
            <strong>{html_lib.escape(self.target)}</strong>
            <div class="target-meta">Generated: {self.timestamp}</div>
        </div>
    </div>
</div>

<div class="main">

    <!-- Risk + Category Stats -->
    <div class="risk-section">
        <div class="gauge-card">
            <div class="gauge">
                <div class="gauge-bg"></div>
                <div class="gauge-fill"></div>
                <div class="gauge-center">
                    <div class="gauge-value">{s['risk']}</div>
                </div>
            </div>
            <div class="risk-label">{s['risk_label']} RISK</div>
            <div style="color: #64748b; font-size: 0.8rem; margin-top: 0.25rem;">out of 100</div>
        </div>
        <div class="stats-grid">
            {category_cards}
        </div>
    </div>

    <!-- Summary Row -->
    <div class="summary-row">
        <div class="summary-card">
            <h3>Total Findings</h3>
            <div class="big">{s['total']}</div>
        </div>
        <div class="summary-card">
            <h3>High Confidence</h3>
            <div class="big">{s['high_count']}</div>
        </div>
        <div class="summary-card">
            <h3>Avg Confidence</h3>
            <div class="big">{s['avg_confidence']:.0f}%</div>
        </div>
        <div class="summary-card">
            <h3>Categories</h3>
            <div class="big">{len(s['categories'])}</div>
        </div>
    </div>

    <!-- Findings Table -->
    <div class="findings-section">
        <h2>All Findings</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Category</th>
                    <th>Finding</th>
                    <th>Value</th>
                    <th>Confidence</th>
                    <th>Source</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>
    </div>

    <!-- Raw JSON -->
    <div class="findings-section">
        <h2>Raw Data (JSON)</h2>
        <pre style="background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 1rem; overflow-x: auto; font-size: 0.8rem; color: #94a3b8; max-height: 500px; overflow-y: auto;">{html_lib.escape(json.dumps(self.to_dict(), indent=2, default=str))}</pre>
    </div>
</div>

<!-- Footer -->
<div class="footer">
    <div class="footer-disclaimer">
        ⚠️ This report was generated by HeavenlyEyes for authorized security testing and OSINT research only.
        Unauthorized use may violate applicable laws. The developers assume no liability for misuse.
    </div>
    <div class="footer-brand">
        Generated by <a href="https://github.com/worldtreeboy/heavenly-eyes">HeavenlyEyes v2.0</a>
        — All-seeing OSINT Reconnaissance
    </div>
</div>

</body>
</html>"""
