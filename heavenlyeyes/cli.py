"""HeavenlyEyes CLI — All-seeing OSINT reconnaissance tool."""

import typer
from typing import Optional
from rich.console import Console

from heavenlyeyes.core.utils import banner, console, print_section, print_info, print_error
from heavenlyeyes.core.config import ensure_config
from heavenlyeyes.core.reporter import ReportCollector

app = typer.Typer(
    name="heavenlyeyes",
    help="HeavenlyEyes — All-seeing OSINT Reconnaissance CLI",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# ── Subcommand groups ──────────────────────────────────────────────────
domain_app = typer.Typer(help="Domain intelligence — WHOIS, DNS, subdomains, SSL, tech stack")
email_app = typer.Typer(help="Email reconnaissance — validation, patterns, breach checks")
social_app = typer.Typer(help="Social network profiling — username search across platforms")
business_app = typer.Typer(help="Business investigation — org info, staff, contacts, records")
leaks_app = typer.Typer(help="Leaked information — breaches, archives, exposed files")

app.add_typer(domain_app, name="domain")
app.add_typer(email_app, name="email")
app.add_typer(social_app, name="social")
app.add_typer(business_app, name="business")
app.add_typer(leaks_app, name="leaks")


# ════════════════════════════════════════════════════════════════════════
#  FULL SCAN
# ════════════════════════════════════════════════════════════════════════

@app.command()
def scan(
    target: str = typer.Argument(help="Target domain to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory for reports"),
    skip_subdomains: bool = typer.Option(False, "--skip-subdomains", help="Skip subdomain enumeration"),
    skip_cloud: bool = typer.Option(False, "--skip-cloud", help="Skip cloud storage check"),
    html: bool = typer.Option(False, "--html", help="Also generate HTML report"),
):
    """Run a full OSINT scan on a target domain."""
    banner()
    ensure_config()
    report = ReportCollector(target)

    from heavenlyeyes.modules.domain.records import whois_lookup, dns_lookup, ssl_info
    from heavenlyeyes.modules.domain.structure import enumerate_subdomains
    from heavenlyeyes.modules.domain.cloud_storage import check_cloud_storage
    from heavenlyeyes.modules.domain.technologies import detect_technologies
    from heavenlyeyes.modules.domain.third_parties import detect_third_parties
    from heavenlyeyes.modules.domain.origin_ip import find_origin_ip
    from heavenlyeyes.modules.email.recon import harvest_emails
    from heavenlyeyes.modules.business.organization import (
        investigate_organization, discover_locations, discover_staff,
        discover_contacts, investigate_records, discover_services,
    )
    from heavenlyeyes.modules.leaks.breaches import (
        check_domain_breaches, check_archives, check_leak_indicators,
    )
    from heavenlyeyes.modules.intelligence.analyzer import analyze_findings

    # Domain
    report.add_section("domain_records", whois_lookup(target))
    report.add_section("dns_records", dns_lookup(target))
    report.add_section("ssl_info", ssl_info(target))

    if not skip_subdomains:
        report.add_section("subdomains", enumerate_subdomains(target))

    report.add_section("technologies", detect_technologies(target))
    report.add_section("third_parties", detect_third_parties(target))

    if not skip_cloud:
        report.add_section("cloud_storage", check_cloud_storage(target))

    # Origin IP (CDN/WAF bypass)
    report.add_section("origin_ip", find_origin_ip(target))

    # Email
    report.add_section("emails", {"harvested": harvest_emails(target)})

    # Business
    report.add_section("organization", investigate_organization(target))
    report.add_section("locations", discover_locations(target))
    report.add_section("staff", discover_staff(target))
    report.add_section("contacts", discover_contacts(target))
    report.add_section("business_records", investigate_records(target))
    report.add_section("services", discover_services(target))

    # Leaks
    report.add_section("breaches", check_domain_breaches(target))
    report.add_section("archives", check_archives(target))
    report.add_section("leak_indicators", check_leak_indicators(target))

    # Intelligence
    assessment = analyze_findings(report.to_dict())
    report.add_section("intelligence", assessment)

    # Save reports
    report.save_json(output)
    if html:
        report.save_html(output)


# ════════════════════════════════════════════════════════════════════════
#  DOMAIN COMMANDS
# ════════════════════════════════════════════════════════════════════════

@domain_app.command("whois")
def cmd_whois(domain: str = typer.Argument(help="Target domain")):
    """Perform WHOIS lookup on a domain."""
    banner()
    from heavenlyeyes.modules.domain.records import whois_lookup
    whois_lookup(domain)


@domain_app.command("dns")
def cmd_dns(domain: str = typer.Argument(help="Target domain")):
    """Query DNS records for a domain."""
    banner()
    from heavenlyeyes.modules.domain.records import dns_lookup
    dns_lookup(domain)


@domain_app.command("subdomains")
def cmd_subdomains(
    domain: str = typer.Argument(help="Target domain"),
    threads: int = typer.Option(20, "--threads", "-t", help="Number of threads"),
):
    """Enumerate subdomains via DNS brute force."""
    banner()
    from heavenlyeyes.modules.domain.structure import enumerate_subdomains
    enumerate_subdomains(domain, threads=threads)


@domain_app.command("ssl")
def cmd_ssl(domain: str = typer.Argument(help="Target domain")):
    """Retrieve SSL/TLS certificate information."""
    banner()
    from heavenlyeyes.modules.domain.records import ssl_info
    ssl_info(domain)


@domain_app.command("tech")
def cmd_tech(domain: str = typer.Argument(help="Target domain")):
    """Detect technologies used by a domain."""
    banner()
    from heavenlyeyes.modules.domain.technologies import detect_technologies
    detect_technologies(domain)


@domain_app.command("cloud")
def cmd_cloud(domain: str = typer.Argument(help="Target domain")):
    """Check for exposed cloud storage buckets."""
    banner()
    from heavenlyeyes.modules.domain.cloud_storage import check_cloud_storage
    check_cloud_storage(domain)


@domain_app.command("third-parties")
def cmd_third_parties(domain: str = typer.Argument(help="Target domain")):
    """Detect third-party services and integrations."""
    banner()
    from heavenlyeyes.modules.domain.third_parties import detect_third_parties
    detect_third_parties(domain)


@domain_app.command("origin")
def cmd_origin(domain: str = typer.Argument(help="Target domain")):
    """Find the real origin IP behind CDN/WAF (Cloudflare, Akamai, etc.)."""
    banner()
    from heavenlyeyes.modules.domain.origin_ip import find_origin_ip
    find_origin_ip(domain)


@domain_app.command("cdn-detect")
def cmd_cdn_detect(domain: str = typer.Argument(help="Target domain")):
    """Detect which CDN/WAF is protecting a domain."""
    banner()
    from heavenlyeyes.modules.domain.origin_ip import detect_cdn_waf
    detect_cdn_waf(domain)


# ════════════════════════════════════════════════════════════════════════
#  EMAIL COMMANDS
# ════════════════════════════════════════════════════════════════════════

@email_app.command("validate")
def cmd_email_validate(email: str = typer.Argument(help="Email address to validate")):
    """Validate an email address (format + MX check)."""
    banner()
    from heavenlyeyes.modules.email.recon import validate_email
    validate_email(email)


@email_app.command("patterns")
def cmd_email_patterns(
    first: str = typer.Argument(help="First name"),
    last: str = typer.Argument(help="Last name"),
    domain: str = typer.Argument(help="Target domain"),
):
    """Generate common email patterns for a person."""
    banner()
    from heavenlyeyes.modules.email.recon import generate_patterns
    generate_patterns(first, last, domain)


@email_app.command("breach")
def cmd_email_breach(email: str = typer.Argument(help="Email address to check")):
    """Check if an email has appeared in known breaches."""
    banner()
    from heavenlyeyes.modules.email.recon import check_breaches
    check_breaches(email)


@email_app.command("harvest")
def cmd_email_harvest(domain: str = typer.Argument(help="Target domain")):
    """Harvest email addresses from a domain's public pages."""
    banner()
    from heavenlyeyes.modules.email.recon import harvest_emails
    harvest_emails(domain)


# ════════════════════════════════════════════════════════════════════════
#  SOCIAL COMMANDS
# ════════════════════════════════════════════════════════════════════════

@social_app.command("username")
def cmd_username(
    username: str = typer.Argument(help="Username to search for"),
    threads: int = typer.Option(15, "--threads", "-t", help="Number of threads"),
):
    """Search for a username across 30+ social platforms."""
    banner()
    from heavenlyeyes.modules.social.networks import search_username
    search_username(username, threads=threads)


@social_app.command("compounded")
def cmd_compounded(username: str = typer.Argument(help="Base username")):
    """Search for related/compounded username variations."""
    banner()
    from heavenlyeyes.modules.social.networks import search_compounded
    search_compounded(username)


# ════════════════════════════════════════════════════════════════════════
#  BUSINESS COMMANDS
# ════════════════════════════════════════════════════════════════════════

@business_app.command("org")
def cmd_org(domain: str = typer.Argument(help="Target domain")):
    """Investigate organization information."""
    banner()
    from heavenlyeyes.modules.business.organization import investigate_organization
    investigate_organization(domain)


@business_app.command("locations")
def cmd_locations(domain: str = typer.Argument(help="Target domain")):
    """Discover physical locations."""
    banner()
    from heavenlyeyes.modules.business.organization import discover_locations
    discover_locations(domain)


@business_app.command("staff")
def cmd_staff(domain: str = typer.Argument(help="Target domain")):
    """Discover staff and team members."""
    banner()
    from heavenlyeyes.modules.business.organization import discover_staff
    discover_staff(domain)


@business_app.command("contacts")
def cmd_contacts(domain: str = typer.Argument(help="Target domain")):
    """Discover contact information."""
    banner()
    from heavenlyeyes.modules.business.organization import discover_contacts
    discover_contacts(domain)


@business_app.command("records")
def cmd_records(domain: str = typer.Argument(help="Target domain")):
    """Investigate business records and registrations."""
    banner()
    from heavenlyeyes.modules.business.organization import investigate_records
    investigate_records(domain)


@business_app.command("services")
def cmd_services(domain: str = typer.Argument(help="Target domain")):
    """Discover services and products offered."""
    banner()
    from heavenlyeyes.modules.business.organization import discover_services
    discover_services(domain)


@business_app.command("full")
def cmd_business_full(
    domain: str = typer.Argument(help="Target domain"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory"),
):
    """Run full business investigation."""
    banner()
    ensure_config()
    report = ReportCollector(domain)

    from heavenlyeyes.modules.business.organization import (
        investigate_organization, discover_locations, discover_staff,
        discover_contacts, investigate_records, discover_services,
    )

    report.add_section("organization", investigate_organization(domain))
    report.add_section("locations", discover_locations(domain))
    report.add_section("staff", discover_staff(domain))
    report.add_section("contacts", discover_contacts(domain))
    report.add_section("business_records", investigate_records(domain))
    report.add_section("services", discover_services(domain))
    report.save_json(output)


# ════════════════════════════════════════════════════════════════════════
#  LEAKS COMMANDS
# ════════════════════════════════════════════════════════════════════════

@leaks_app.command("breaches")
def cmd_breaches(domain: str = typer.Argument(help="Target domain")):
    """Check if a domain has been involved in known breaches."""
    banner()
    from heavenlyeyes.modules.leaks.breaches import check_domain_breaches
    check_domain_breaches(domain)


@leaks_app.command("archives")
def cmd_archives(domain: str = typer.Argument(help="Target domain")):
    """Check Wayback Machine for archived snapshots."""
    banner()
    from heavenlyeyes.modules.leaks.breaches import check_archives
    check_archives(domain)


@leaks_app.command("exposed")
def cmd_exposed(domain: str = typer.Argument(help="Target domain")):
    """Check for exposed sensitive files and paths."""
    banner()
    from heavenlyeyes.modules.leaks.breaches import check_leak_indicators
    check_leak_indicators(domain)


@leaks_app.command("pastes")
def cmd_pastes(query: str = typer.Argument(help="Search query (domain, email, etc.)")):
    """Search for mentions on paste sites and public repos."""
    banner()
    from heavenlyeyes.modules.leaks.breaches import check_pastes
    check_pastes(query)


@leaks_app.command("full")
def cmd_leaks_full(
    domain: str = typer.Argument(help="Target domain"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory"),
):
    """Run full leak investigation."""
    banner()
    ensure_config()
    report = ReportCollector(domain)

    from heavenlyeyes.modules.leaks.breaches import (
        check_domain_breaches, check_archives, check_leak_indicators, check_pastes,
    )

    report.add_section("breaches", check_domain_breaches(domain))
    report.add_section("archives", check_archives(domain))
    report.add_section("leak_indicators", check_leak_indicators(domain))
    report.add_section("pastes", check_pastes(domain))
    report.save_json(output)


# ════════════════════════════════════════════════════════════════════════
#  PIVOT — RECURSIVE OSINT ENGINE (v2)
# ════════════════════════════════════════════════════════════════════════

@app.command()
def pivot(
    target: str = typer.Argument(help="Target — username, email, domain, or IP"),
    depth: int = typer.Option(2, "--depth", "-d", help="Max recursive pivot depth (1-4)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory"),
    no_dorking: bool = typer.Option(False, "--no-dorking", help="Skip Google Dorking"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI synthesis"),
    html: bool = typer.Option(False, "--html", help="Also generate HTML report"),
    stealth_min: float = typer.Option(0.5, "--stealth-min", help="Min delay between requests (sec)"),
    stealth_max: float = typer.Option(3.0, "--stealth-max", help="Max delay between requests (sec)"),
):
    """[bold cyan]Recursive Pivot Engine[/bold cyan] — give it a username, email, domain, or IP and it branches out automatically to map the full digital footprint.

    \b
    Examples:
      heavenlyeyes pivot johndoe
      heavenlyeyes pivot user@example.com --depth 3
      heavenlyeyes pivot example.com --no-dorking --html
      heavenlyeyes pivot 1.2.3.4 -d 1 -o ./reports
    """
    ensure_config()
    depth = max(1, min(4, depth))

    from heavenlyeyes.engine.stealth import StealthConfig
    from heavenlyeyes.engine.pivot import RecursivePivotEngine

    stealth_cfg = StealthConfig(min_delay=stealth_min, max_delay=stealth_max)
    engine = RecursivePivotEngine(
        max_depth=depth,
        enable_dorking=not no_dorking,
        enable_ai=not no_ai,
        stealth_config=stealth_cfg,
    )
    engine.run(target, output_dir=output, html=html)


# ════════════════════════════════════════════════════════════════════════
#  DORKING
# ════════════════════════════════════════════════════════════════════════

@app.command()
def dork(
    target: str = typer.Argument(help="Target domain, username, or email"),
    execute: bool = typer.Option(False, "--execute", "-x", help="Execute dorks (default: just list them)"),
    max_dorks: int = typer.Option(20, "--max", "-m", help="Max dorks to execute"),
):
    """[bold cyan]Google Dorking Engine[/bold cyan] — generate or execute advanced search queries for exposed data.

    \b
    Examples:
      heavenlyeyes dork example.com              # List dork queries
      heavenlyeyes dork example.com --execute    # Execute with stealth
      heavenlyeyes dork johndoe -x -m 10
    """
    ensure_config()
    from heavenlyeyes.engine.pivot import classify_input
    from heavenlyeyes.engine.dorking import DorkingEngine
    from heavenlyeyes.engine.dashboard import print_banner, print_disclaimer

    print_banner()
    print_disclaimer()

    input_type = classify_input(target)
    engine = DorkingEngine()

    if execute:
        engine.execute_dorks(target, target_type=input_type, max_dorks=max_dorks)
    else:
        dorks = engine.get_dork_report(target, target_type=input_type)
        from rich.table import Table
        from rich import box
        table = Table(
            title=f"[bold]Google Dorks for {target}[/bold]",
            box=box.ROUNDED, border_style="cyan",
            header_style="bold white on #1a1a2e",
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Category", style="cyan", width=20)
        table.add_column("Query", style="white")
        for i, d in enumerate(dorks, 1):
            table.add_row(str(i), d["category"], d["query"])
        console.print(table)
        console.print(f"\n[dim]{len(dorks)} dork(s) generated — use --execute to run them[/dim]")


# ════════════════════════════════════════════════════════════════════════
#  CONFIG COMMAND
# ════════════════════════════════════════════════════════════════════════

@app.command()
def config():
    """Initialize or show configuration."""
    ensure_config()
    from heavenlyeyes.core.config import CONFIG_FILE
    print_info(f"Config file: {CONFIG_FILE}")
    print_info("Edit this file to add API keys and customize settings.")
    print_info("You can also set API keys via environment variables:")
    print_info("  HEYES_SHODAN, HEYES_HAVEIBEENPWNED, HEYES_HUNTER_IO, HEYES_VIRUSTOTAL")
    print_info("  ANTHROPIC_API_KEY, OPENAI_API_KEY (for AI synthesis)")


# ════════════════════════════════════════════════════════════════════════
#  VERSION
# ════════════════════════════════════════════════════════════════════════

@app.command()
def version():
    """Show HeavenlyEyes version."""
    from heavenlyeyes import __version__
    console.print(f"[bold cyan]HeavenlyEyes[/bold cyan] v{__version__}")


if __name__ == "__main__":
    app()
