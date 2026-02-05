"""AI Synthesis Module — LLM-powered analysis of OSINT findings."""

import json
import os

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

from heavenlyeyes.engine.confidence import Finding
from heavenlyeyes.engine.dashboard import console
from heavenlyeyes.core.config import get_api_key

SYSTEM_PROMPT = """You are HeavenlyEyes AI — an expert OSINT analyst. You are given raw
reconnaissance findings about a target. Your job is to produce a concise, professional
"Digital Footprint Summary" that a security researcher or red team operator would find useful.

Structure your analysis as:
1. **Identity Overview** — Who/what is the target based on the data?
2. **Digital Presence** — Where do they exist online? How active?
3. **Attack Surface** — What exposures, misconfigurations, or risks are visible?
4. **Key Correlations** — What connections between data points stand out?
5. **Risk Assessment** — Overall exposure level (LOW/MEDIUM/HIGH/CRITICAL) with justification.
6. **Recommendations** — Top 3-5 actionable items.

Be concise. Use bullet points. Do not speculate beyond what the data supports.
If confidence scores are low, note the uncertainty."""


def _format_findings_for_llm(target: str, findings: list[Finding]) -> str:
    """Convert findings into a structured text block for the LLM."""
    lines = [f"TARGET: {target}", f"TOTAL FINDINGS: {len(findings)}", ""]

    by_category = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    for cat, items in sorted(by_category.items()):
        lines.append(f"== {cat.upper()} ({len(items)} findings) ==")
        for f in sorted(items, key=lambda x: x.confidence, reverse=True):
            lines.append(
                f"  [{f.confidence}% {f.confidence_label}] {f.label}: {f.value}"
                f"  (source: {f.source})"
            )
        lines.append("")

    return "\n".join(lines)


class AISynthesizer:
    """Uses an LLM to analyze OSINT findings and generate intelligence reports."""

    def __init__(self):
        self.provider = None
        self.api_key = None
        self._detect_provider()

    def _detect_provider(self):
        """Auto-detect available LLM provider from API keys."""
        # Check Anthropic first
        key = get_api_key("anthropic") or os.environ.get("ANTHROPIC_API_KEY", "")
        if key:
            self.provider = "anthropic"
            self.api_key = key
            return

        # Check OpenAI
        key = get_api_key("openai") or os.environ.get("OPENAI_API_KEY", "")
        if key:
            self.provider = "openai"
            self.api_key = key
            return

    @property
    def available(self) -> bool:
        return self.provider is not None and self.api_key is not None

    def synthesize(self, target: str, findings: list[Finding]) -> str:
        """Generate AI-powered Digital Footprint Summary."""
        if not self.available:
            return self._fallback_synthesis(target, findings)

        findings_text = _format_findings_for_llm(target, findings)
        prompt = (
            f"Analyze the following OSINT reconnaissance data and produce a "
            f"Digital Footprint Summary.\n\n{findings_text}"
        )

        if self.provider == "anthropic":
            return self._call_anthropic(prompt)
        elif self.provider == "openai":
            return self._call_openai(prompt)

        return self._fallback_synthesis(target, findings)

    def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic Claude API."""
        import requests
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-5-20250929",
                "max_tokens": 2000,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=60,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data["content"][0]["text"]
        else:
            console.print(f"  [yellow]Anthropic API error ({resp.status_code}), using fallback[/yellow]")
            return ""

    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API."""
        import requests
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 2000,
            },
            timeout=60,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        else:
            console.print(f"  [yellow]OpenAI API error ({resp.status_code}), using fallback[/yellow]")
            return ""

    def _fallback_synthesis(self, target: str, findings: list[Finding]) -> str:
        """Rule-based synthesis when no LLM is available."""
        by_category = {}
        for f in findings:
            by_category.setdefault(f.category, []).append(f)

        total = len(findings)
        high_conf = [f for f in findings if f.confidence >= 75]
        avg_conf = sum(f.confidence for f in findings) / total if total else 0

        lines = [
            f"# Digital Footprint Summary — {target}",
            "",
            "## Identity Overview",
            f"- Target: **{target}**",
            f"- Total findings: **{total}** ({len(high_conf)} high confidence)",
            f"- Average confidence: **{avg_conf:.0f}%**",
            "",
            "## Digital Presence",
        ]

        if "social_profile" in by_category:
            profiles = by_category["social_profile"]
            lines.append(f"- **{len(profiles)}** social media profiles identified")
            for p in sorted(profiles, key=lambda x: x.confidence, reverse=True)[:5]:
                lines.append(f"  - {p.label}: {p.value} ({p.confidence}%)")

        if "domain" in by_category or "dns" in by_category:
            domain_findings = by_category.get("domain", []) + by_category.get("dns", [])
            lines.append(f"- **{len(domain_findings)}** domain/infrastructure findings")

        if "email" in by_category:
            lines.append(f"- **{len(by_category['email'])}** email addresses found")

        lines.append("")
        lines.append("## Attack Surface")

        risk_items = []
        if "config_files" in by_category:
            risk_items.append(f"- **Exposed config files**: {len(by_category['config_files'])} found")
        if "data_exposure" in by_category:
            risk_items.append(f"- **Data exposure**: {len(by_category['data_exposure'])} findings")
        if "breach" in by_category:
            risk_items.append(f"- **Breach data**: {len(by_category['breach'])} records")
        if "exposed_paths" in by_category:
            risk_items.append(f"- **Exposed sensitive paths**: {len(by_category['exposed_paths'])} found")

        if risk_items:
            lines.extend(risk_items)
        else:
            lines.append("- No critical exposures detected in findings")

        lines.append("")
        lines.append("## Risk Assessment")
        risk_score = min(100, total * 3 + len(high_conf) * 5)
        if risk_score >= 70:
            lines.append(f"- **CRITICAL** (Score: {risk_score}/100)")
        elif risk_score >= 50:
            lines.append(f"- **HIGH** (Score: {risk_score}/100)")
        elif risk_score >= 30:
            lines.append(f"- **MEDIUM** (Score: {risk_score}/100)")
        else:
            lines.append(f"- **LOW** (Score: {risk_score}/100)")

        lines.extend([
            "",
            "## Recommendations",
            "1. Review all high-confidence findings for actionable intelligence",
            "2. Cross-reference social profiles for identity correlation",
            "3. Investigate any exposed configuration files or credentials",
            "4. Check breach data for compromised credentials",
            "5. Monitor identified infrastructure for changes",
            "",
            "---",
            "*Generated by HeavenlyEyes AI Synthesis (rule-based fallback)*",
            "*Add an ANTHROPIC_API_KEY or OPENAI_API_KEY for LLM-powered analysis*",
        ])

        return "\n".join(lines)

    def display_synthesis(self, target: str, findings: list[Finding]):
        """Run synthesis and display results."""
        console.print("\n")
        if self.available:
            console.print(
                f"  [bold cyan]🧠 AI Synthesis[/bold cyan] "
                f"[dim](provider: {self.provider})[/dim]"
            )
        else:
            console.print(
                "  [bold cyan]🧠 AI Synthesis[/bold cyan] "
                "[dim](rule-based — add LLM API key for AI analysis)[/dim]"
            )

        report = self.synthesize(target, findings)
        if report:
            console.print(Panel(
                Markdown(report),
                title="[bold]Digital Footprint Summary[/bold]",
                border_style="cyan",
                padding=(1, 3),
            ))
        return report
