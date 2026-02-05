"""Report generation for HeavenlyEyes."""

import json
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
            "version": "1.0.0",
            "target": self.target,
            "timestamp": self.timestamp,
            "findings": self.sections,
        }

    def save_json(self, output_dir: str | None = None) -> Path:
        if output_dir:
            out = Path(output_dir)
        else:
            out = Path.cwd() / "heyes_reports"
        out.mkdir(parents=True, exist_ok=True)

        safe_target = self.target.replace("/", "_").replace(":", "_").replace("@", "_at_")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = out / f"heyes_{safe_target}_{ts}.json"

        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

        console.print(f"\n[green]Report saved:[/green] {filepath}")
        return filepath

    def save_html(self, output_dir: str | None = None) -> Path:
        if output_dir:
            out = Path(output_dir)
        else:
            out = Path.cwd() / "heyes_reports"
        out.mkdir(parents=True, exist_ok=True)

        safe_target = self.target.replace("/", "_").replace(":", "_").replace("@", "_at_")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = out / f"heyes_{safe_target}_{ts}.html"

        html = self._render_html()
        with open(filepath, "w") as f:
            f.write(html)

        console.print(f"[green]HTML Report saved:[/green] {filepath}")
        return filepath

    def _render_html(self) -> str:
        sections_html = ""
        for name, data in self.sections.items():
            items = ""
            for key, val in data.items():
                if isinstance(val, list):
                    val_str = "<br>".join(str(v) for v in val)
                elif isinstance(val, dict):
                    val_str = "<pre>" + json.dumps(val, indent=2, default=str) + "</pre>"
                else:
                    val_str = str(val)
                items += f"<tr><td><strong>{key}</strong></td><td>{val_str}</td></tr>\n"
            sections_html += f"""
            <div class="section">
                <h2>{name}</h2>
                <table><tbody>{items}</tbody></table>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HeavenlyEyes Report — {self.target}</title>
<style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #0a0a0f; color: #e0e0e0; margin: 2rem; }}
    h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 0.5rem; }}
    h2 {{ color: #00d4ff; margin-top: 2rem; }}
    .meta {{ color: #888; font-size: 0.9rem; }}
    .section {{ background: #12121a; border: 1px solid #1e1e2e; border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td {{ padding: 0.5rem; border-bottom: 1px solid #1e1e2e; vertical-align: top; }}
    td:first-child {{ width: 200px; color: #00d4ff; }}
    pre {{ background: #1a1a2e; padding: 0.5rem; border-radius: 4px; overflow-x: auto; }}
</style>
</head>
<body>
<h1>HeavenlyEyes Report</h1>
<p class="meta">Target: <strong>{self.target}</strong> | Generated: {self.timestamp}</p>
{sections_html}
</body>
</html>"""
