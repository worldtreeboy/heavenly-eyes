"""Intelligence analyzer — correlates findings and generates assessments."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from heavenlyeyes.core.utils import print_section, print_found, print_warning, print_info, console


def analyze_findings(report_data: dict) -> dict:
    """Analyze collected OSINT data and produce intelligence assessment."""
    print_section("Intelligence Analysis")

    findings = report_data.get("findings", {})
    assessment = {
        "risk_score": 0,
        "risk_level": "LOW",
        "findings_summary": {},
        "recommendations": [],
        "attack_surface": [],
    }

    total_risks = 0
    max_risk = 0

    # ── Analyze domain info ──
    domain_data = findings.get("domain_records", {})
    if domain_data:
        assessment["findings_summary"]["domain"] = "WHOIS and DNS records retrieved"
        if domain_data.get("registrant_email"):
            assessment["attack_surface"].append("Registrant email exposed in WHOIS")
            total_risks += 1

    # ── Analyze subdomains ──
    subdomains = findings.get("subdomains", {})
    if subdomains:
        count = len(subdomains)
        assessment["findings_summary"]["subdomains"] = f"{count} subdomains discovered"
        if count > 20:
            assessment["attack_surface"].append(f"Large attack surface: {count} subdomains")
            total_risks += 2
        sensitive_subs = [s for s in subdomains if any(kw in s for kw in
                         ("admin", "staging", "dev", "test", "internal", "vpn", "jenkins", "git"))]
        if sensitive_subs:
            assessment["attack_surface"].append(f"Sensitive subdomains found: {', '.join(sensitive_subs[:5])}")
            total_risks += 3
            assessment["recommendations"].append("Review and restrict access to sensitive subdomains")

    # ── Analyze SSL ──
    ssl_data = findings.get("ssl_info", {})
    if ssl_data:
        not_after = ssl_data.get("not_after", "")
        assessment["findings_summary"]["ssl"] = "SSL certificate information retrieved"

    # ── Analyze cloud storage ──
    cloud = findings.get("cloud_storage", {})
    if cloud:
        public_buckets = [k for k, v in cloud.items() if v.get("status") == "PUBLIC"]
        if public_buckets:
            total_risks += 5
            assessment["attack_surface"].append(f"PUBLIC cloud storage buckets: {len(public_buckets)}")
            assessment["recommendations"].append("Immediately review and secure public cloud storage buckets")

    # ── Analyze technologies ──
    tech = findings.get("technologies", {})
    if tech:
        assessment["findings_summary"]["technologies"] = f"{len(tech)} technologies detected"
        sec_headers = tech.get("Security Headers", {})
        if not sec_headers:
            total_risks += 2
            assessment["recommendations"].append("Implement security headers (HSTS, CSP, X-Frame-Options)")

    # ── Analyze emails ──
    emails = findings.get("emails", [])
    if emails:
        assessment["findings_summary"]["emails"] = f"{len(emails)} email(s) harvested"
        if len(emails) > 5:
            total_risks += 1
            assessment["recommendations"].append("Review exposed email addresses for phishing risk")

    # ── Analyze social profiles ──
    social = findings.get("social_profiles", {})
    if social:
        assessment["findings_summary"]["social"] = f"{len(social)} social profiles found"

    # ── Analyze breaches ──
    breaches = findings.get("breaches", {})
    if breaches:
        breach_list = breaches.get("breaches", [])
        if breach_list:
            total_risks += 4
            assessment["findings_summary"]["breaches"] = f"Found in {len(breach_list)} breach(es)"
            assessment["recommendations"].append("Audit compromised credentials and enforce password resets")

    # ── Analyze leak indicators ──
    leaks = findings.get("leak_indicators", {})
    if leaks:
        total_risks += 3 * len(leaks)
        assessment["findings_summary"]["exposed_paths"] = f"{len(leaks)} sensitive path(s) exposed"
        assessment["recommendations"].append("Remove or restrict access to exposed sensitive files")

    # ── Analyze archives ──
    archives = findings.get("archives", {})
    if archives and archives.get("snapshots"):
        assessment["findings_summary"]["archives"] = f"{len(archives['snapshots'])} web archive snapshots"

    # ── Calculate risk score ──
    assessment["risk_score"] = min(total_risks * 10, 100)
    if assessment["risk_score"] >= 70:
        assessment["risk_level"] = "CRITICAL"
    elif assessment["risk_score"] >= 50:
        assessment["risk_level"] = "HIGH"
    elif assessment["risk_score"] >= 30:
        assessment["risk_level"] = "MEDIUM"
    else:
        assessment["risk_level"] = "LOW"

    # ── Display assessment ──
    risk_color = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "bold red",
    }.get(assessment["risk_level"], "white")

    console.print(Panel(
        f"[{risk_color}]{assessment['risk_level']}[/{risk_color}] — Score: {assessment['risk_score']}/100",
        title="[bold]Risk Assessment[/bold]",
        border_style=risk_color,
    ))

    # Summary table
    if assessment["findings_summary"]:
        table = Table(title="Findings Summary", border_style="cyan")
        table.add_column("Category", style="cyan")
        table.add_column("Finding", style="white")
        for cat, finding in assessment["findings_summary"].items():
            table.add_row(cat.replace("_", " ").title(), finding)
        console.print(table)

    # Attack surface
    if assessment["attack_surface"]:
        console.print("\n[bold red]Attack Surface:[/bold red]")
        for item in assessment["attack_surface"]:
            print_warning(item)

    # Recommendations
    if assessment["recommendations"]:
        console.print("\n[bold cyan]Recommendations:[/bold cyan]")
        for i, rec in enumerate(assessment["recommendations"], 1):
            print_info(f"{i}. {rec}")
    else:
        print_info("No critical recommendations at this time")

    return assessment
