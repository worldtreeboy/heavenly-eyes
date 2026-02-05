"""HeavenlyEyes CLI — All-seeing OSINT reconnaissance tool."""

import typer
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from heavenlyeyes.core.utils import banner, console, print_section, print_info, print_error
from heavenlyeyes.core.config import ensure_config, auto_check_keys
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
osint_app = typer.Typer(help="Deep OSINT — phone, EXIF, dark web, CT logs, WiFi geolocation")

app.add_typer(domain_app, name="domain")
app.add_typer(email_app, name="email")
app.add_typer(social_app, name="social")
app.add_typer(business_app, name="business")
app.add_typer(leaks_app, name="leaks")
app.add_typer(osint_app, name="osint")


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
    parallel: bool = typer.Option(True, "--parallel/--sequential", help="Run modules in parallel"),
    workers: int = typer.Option(6, "--workers", "-w", help="Max parallel workers (2-12)"),
):
    """Run a full OSINT scan on a target domain."""
    banner()
    ensure_config()
    auto_check_keys(console)
    report = ReportCollector(target)
    workers = max(2, min(12, workers))

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

    # ── Build task list ──
    tasks = [
        ("domain_records", "WHOIS Lookup", lambda: whois_lookup(target)),
        ("dns_records", "DNS Records", lambda: dns_lookup(target)),
        ("ssl_info", "SSL Certificate", lambda: ssl_info(target)),
        ("technologies", "Tech Detection", lambda: detect_technologies(target)),
        ("third_parties", "Third Parties", lambda: detect_third_parties(target)),
        ("origin_ip", "Origin IP Discovery", lambda: find_origin_ip(target)),
        ("emails", "Email Harvesting", lambda: {"harvested": harvest_emails(target)}),
        ("organization", "Organization Intel", lambda: investigate_organization(target)),
        ("locations", "Locations", lambda: discover_locations(target)),
        ("staff", "Staff Discovery", lambda: discover_staff(target)),
        ("contacts", "Contacts", lambda: discover_contacts(target)),
        ("business_records", "Business Records", lambda: investigate_records(target)),
        ("services", "Services", lambda: discover_services(target)),
        ("breaches", "Breach Check", lambda: check_domain_breaches(target)),
        ("archives", "Web Archives", lambda: check_archives(target)),
        ("leak_indicators", "Leak Indicators", lambda: check_leak_indicators(target)),
    ]

    if not skip_subdomains:
        tasks.insert(3, ("subdomains", "Subdomain Enum", lambda: enumerate_subdomains(target)))

    if not skip_cloud:
        tasks.insert(4, ("cloud_storage", "Cloud Storage", lambda: check_cloud_storage(target)))

    # ── Execute ──
    if parallel:
        console.print(f"\n[bold cyan]Parallel scan[/bold cyan] — {len(tasks)} modules, {workers} workers\n")

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=20, complete_style="cyan"),
            TextColumn("[dim]{task.fields[status]}[/dim]"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            progress_tasks = {}
            for section_key, label, _ in tasks:
                progress_tasks[section_key] = progress.add_task(label, total=1, status="pending")

            def _run_module(section_key, label, fn):
                progress.update(progress_tasks[section_key], status="running...")
                try:
                    result = fn()
                    progress.update(progress_tasks[section_key], advance=1, status="[green]done[/green]")
                    return section_key, result
                except Exception as e:
                    progress.update(progress_tasks[section_key], advance=1, status=f"[red]error[/red]")
                    return section_key, {"error": str(e)}

            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(_run_module, key, label, fn): key
                    for key, label, fn in tasks
                }
                for future in as_completed(futures):
                    section_key, result = future.result()
                    report.add_section(section_key, result)
    else:
        for section_key, label, fn in tasks:
            print_section(label)
            try:
                report.add_section(section_key, fn())
            except Exception as e:
                print_error(f"{label} failed: {e}")
                report.add_section(section_key, {"error": str(e)})

    # Intelligence analysis (runs after all modules complete)
    print_section("Intelligence Analysis")
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
    auto_check_keys(console)
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
#  SETUP WIZARD
# ════════════════════════════════════════════════════════════════════════

@app.command()
def setup():
    """[bold cyan]Setup Wizard[/bold cyan] — configure API keys interactively.

    \b
    Walks you through each API key, shows what features it unlocks,
    and offers to open sign-up pages in your browser.
    Keys are saved in ~/.heavenlyeyes/config.yaml
    """
    banner()
    from heavenlyeyes.core.config import setup_wizard
    setup_wizard(console)


@app.command()
def config():
    """Show current configuration and API key status."""
    banner()
    from heavenlyeyes.core.config import (
        CONFIG_FILE, check_missing_keys, get_api_key,
        API_KEY_REGISTRY, AI_KEY_REGISTRY, _mask_key,
    )
    from rich.table import Table
    from rich import box
    import os

    ensure_config()

    table = Table(
        title="[bold]Configuration Status[/bold]",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold white on #1a1a2e",
    )
    table.add_column("Service", style="white", width=22)
    table.add_column("Status", width=16, justify="center")
    table.add_column("Source", style="dim", width=10)

    all_keys = {**API_KEY_REGISTRY, **AI_KEY_REGISTRY}
    for key_name, info in all_keys.items():
        val = get_api_key(key_name)
        if not val and key_name in AI_KEY_REGISTRY:
            val = os.environ.get(info["env"], "")

        if val:
            source = "env" if os.environ.get(info["env"]) else "config"
            status = f"[bold green]✔ {_mask_key(val)}[/bold green]"
        else:
            source = "-"
            status = "[red]✘ Missing[/red]"
        table.add_row(info["name"], status, source)

    console.print(table)
    console.print(f"\n[dim]Config file: {CONFIG_FILE}[/dim]")
    console.print("[dim]Run [bold]heavenlyeyes setup[/bold] to configure missing keys.[/dim]\n")


# ════════════════════════════════════════════════════════════════════════
#  DEEP OSINT COMMANDS
# ════════════════════════════════════════════════════════════════════════

@osint_app.command("phone")
def cmd_phone(phone: str = typer.Argument(help="Phone number (e.g. +1234567890)")):
    """Phone number OSINT — carrier, format, social accounts, reverse lookup."""
    banner()
    from heavenlyeyes.modules.osint.phone import phone_lookup
    phone_lookup(phone)


@osint_app.command("exif")
def cmd_exif(
    source: str = typer.Argument(help="Image URL or local file path"),
):
    """Extract EXIF metadata from images — GPS, device, timestamps, privacy risks."""
    banner()
    from heavenlyeyes.modules.osint.exif import extract_exif
    extract_exif(source)


@osint_app.command("darkweb")
def cmd_darkweb(
    query: str = typer.Argument(help="Email, domain, or username to search"),
    query_type: str = typer.Option("auto", "--type", "-t", help="Query type: auto, email, domain, username"),
):
    """Dark web monitor — IntelligenceX, Dehashed, breach pastes, leaked credentials."""
    banner()
    from heavenlyeyes.modules.osint.darkweb import darkweb_scan
    darkweb_scan(query, query_type)


@osint_app.command("ct-scan")
def cmd_ct_scan(
    domain: str = typer.Argument(help="Target domain"),
    no_resolve: bool = typer.Option(False, "--no-resolve", help="Skip DNS resolution of subdomains"),
):
    """Certificate Transparency scan — discover subdomains from CT logs."""
    banner()
    from heavenlyeyes.modules.osint.ctmonitor import ct_scan
    ct_scan(domain, resolve=not no_resolve)


@osint_app.command("ct-watch")
def cmd_ct_watch(
    domain: str = typer.Argument(help="Target domain"),
    interval: int = typer.Option(60, "--interval", "-i", help="Check interval in minutes"),
    checks: int = typer.Option(24, "--checks", "-n", help="Max number of checks"),
):
    """CT log watch mode — continuously monitor for new certificates."""
    banner()
    from heavenlyeyes.modules.osint.ctmonitor import ct_watch
    ct_watch(domain, interval_minutes=interval, max_checks=checks)


@osint_app.command("wifi")
def cmd_wifi(query: str = typer.Argument(help="Organization name or SSID to search")):
    """WiFi SSID intelligence — search for wireless networks linked to a target."""
    banner()
    from heavenlyeyes.modules.osint.wifi import wifi_ssid_search
    wifi_ssid_search(query)


@osint_app.command("wifi-location")
def cmd_wifi_location(
    lat: float = typer.Argument(help="Latitude"),
    lon: float = typer.Argument(help="Longitude"),
    radius: float = typer.Option(0.5, "--radius", "-r", help="Search radius in km"),
):
    """Search for WiFi networks near a GPS location."""
    banner()
    from heavenlyeyes.modules.osint.wifi import wifi_location_search
    wifi_location_search(lat, lon, radius)


@osint_app.command("wifi-bssid")
def cmd_wifi_bssid(bssid: str = typer.Argument(help="BSSID / MAC address (XX:XX:XX:XX:XX:XX)")):
    """Geolocate a specific WiFi access point by BSSID."""
    banner()
    from heavenlyeyes.modules.osint.wifi import wifi_bssid_lookup
    wifi_bssid_lookup(bssid)


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
