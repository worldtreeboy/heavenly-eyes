"""Certificate Transparency Log Monitor — real-time subdomain discovery."""

import json
import time
import re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from heavenlyeyes.core.utils import (
    console, make_request, print_section, print_found, print_not_found,
    print_info, print_warning, print_error, create_table, resolve_host,
)
from heavenlyeyes.core.config import get_api_key

# ── CT Log Sources ────────────────────────────────────────────────────

def _search_crtsh(domain: str, recent_days: int = 0) -> list:
    """Search crt.sh for certificate transparency logs."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    if recent_days > 0:
        after = (datetime.utcnow() - timedelta(days=recent_days)).strftime("%Y-%m-%d")
        url += f"&exclude=expired&after={after}"

    resp = make_request(url, timeout=30)
    if not resp or resp.status_code != 200:
        return []

    try:
        entries = resp.json()
    except Exception:
        return []

    results = []
    seen = set()

    for entry in entries:
        name_value = entry.get("name_value", "")
        # Split multi-line CN/SAN entries
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and name not in seen and domain.lower() in name:
                seen.add(name)
                results.append({
                    "subdomain": name,
                    "issuer": entry.get("issuer_name", "Unknown"),
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                    "serial": entry.get("serial_number", ""),
                    "id": entry.get("id", ""),
                })

    return results


def _search_certspotter(domain: str) -> list:
    """Search Cert Spotter API (SSLMate) — free tier: 100 req/hr."""
    resp = make_request(
        f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
        timeout=20,
    )
    if not resp or resp.status_code != 200:
        return []

    results = []
    seen = set()

    try:
        for entry in resp.json():
            for name in entry.get("dns_names", []):
                name = name.strip().lower()
                if name not in seen and domain.lower() in name:
                    seen.add(name)
                    results.append({
                        "subdomain": name,
                        "issuer": entry.get("issuer", {}).get("name", "Unknown") if isinstance(entry.get("issuer"), dict) else str(entry.get("issuer", "Unknown")),
                        "not_before": entry.get("not_before", ""),
                        "not_after": entry.get("not_after", ""),
                    })
    except Exception:
        pass

    return results


def _search_censys_certs(domain: str) -> list:
    """Search Censys certificate dataset for subdomains."""
    censys_id = get_api_key("censys_id")
    censys_secret = get_api_key("censys_secret")
    if not censys_id or not censys_secret:
        return []

    resp = make_request(
        "https://search.censys.io/api/v2/certificates/search",
        method="POST",
        auth=(censys_id, censys_secret),
        json={
            "q": f"names: {domain}",
            "per_page": 100,
        },
    )

    if not resp or resp.status_code != 200:
        return []

    results = []
    seen = set()

    try:
        for hit in resp.json().get("result", {}).get("hits", []):
            for name in hit.get("names", []):
                name = name.strip().lower()
                if name not in seen and domain.lower() in name:
                    seen.add(name)
                    results.append({
                        "subdomain": name,
                        "issuer": hit.get("parsed", {}).get("issuer_dn", "Unknown") if isinstance(hit.get("parsed"), dict) else "Unknown",
                        "fingerprint": hit.get("fingerprint_sha256", "")[:16] + "...",
                    })
    except Exception:
        pass

    return results


def _search_google_ct(domain: str) -> list:
    """Search Google Certificate Transparency log."""
    resp = make_request(
        f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=false&include_subdomains=true&domain={domain}",
        timeout=20,
    )
    if not resp or resp.status_code != 200:
        return []

    results = []
    seen = set()
    # Google's API returns a weird format with prefixed JSON
    text = resp.text
    try:
        # Strip security prefix
        if text.startswith(")]}'"):
            text = text[4:]
        data = json.loads(text)
        # Navigate nested arrays
        entries = data[0][1] if data and len(data) > 0 and len(data[0]) > 1 else []
        for entry in entries:
            if isinstance(entry, list) and len(entry) >= 2:
                name = entry[1].strip().lower() if isinstance(entry[1], str) else ""
                if name and name not in seen and domain.lower() in name:
                    seen.add(name)
                    results.append({"subdomain": name, "issuer": "Google CT"})
    except Exception:
        pass

    return results


# ── DNS Resolution for discovered subdomains ──────────────────────────

def _resolve_subdomains(subdomains: list, max_workers: int = 30) -> dict:
    """Resolve discovered subdomains to IPs."""
    resolved = {}

    def _resolve(sub):
        ip = resolve_host(sub)
        return sub, ip

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_resolve, s["subdomain"]): s["subdomain"] for s in subdomains}
        for future in as_completed(futures):
            sub, ip = future.result()
            if ip:
                resolved[sub] = ip

    return resolved


# ── New Certificate Detection ─────────────────────────────────────────

def _detect_new_certs(domain: str, since_hours: int = 24) -> list:
    """Find certificates issued in the last N hours."""
    all_certs = _search_crtsh(domain, recent_days=max(1, since_hours // 24))

    cutoff = datetime.utcnow() - timedelta(hours=since_hours)
    new_certs = []

    for cert in all_certs:
        not_before = cert.get("not_before", "")
        if not_before:
            try:
                cert_date = datetime.strptime(not_before[:19], "%Y-%m-%dT%H:%M:%S")
                if cert_date >= cutoff:
                    cert["age_hours"] = int((datetime.utcnow() - cert_date).total_seconds() / 3600)
                    new_certs.append(cert)
            except ValueError:
                pass

    return sorted(new_certs, key=lambda x: x.get("not_before", ""), reverse=True)


# ── Wildcard & Issuer Analysis ────────────────────────────────────────

def _analyze_certs(certs: list) -> dict:
    """Analyze certificate patterns for security insights."""
    analysis = {
        "total_unique_subdomains": 0,
        "wildcard_certs": [],
        "issuers": {},
        "recently_issued": [],
        "expiring_soon": [],
    }

    subdomains = set()
    now = datetime.utcnow()

    for cert in certs:
        sub = cert.get("subdomain", "")
        subdomains.add(sub)

        # Wildcards
        if sub.startswith("*."):
            analysis["wildcard_certs"].append(sub)

        # Issuer tracking
        issuer = cert.get("issuer", "Unknown")
        # Extract common name from issuer string
        if "CN=" in issuer:
            issuer = issuer.split("CN=")[1].split(",")[0].strip()
        analysis["issuers"][issuer] = analysis["issuers"].get(issuer, 0) + 1

        # Check expiring soon (within 30 days)
        not_after = cert.get("not_after", "")
        if not_after:
            try:
                exp_date = datetime.strptime(not_after[:19], "%Y-%m-%dT%H:%M:%S")
                if now < exp_date < now + timedelta(days=30):
                    analysis["expiring_soon"].append({
                        "subdomain": sub,
                        "expires": not_after[:10],
                        "days_left": (exp_date - now).days,
                    })
            except ValueError:
                pass

    analysis["total_unique_subdomains"] = len(subdomains)
    return analysis


# ════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ════════════════════════════════════════════════════════════════════════

def ct_scan(domain: str, resolve: bool = True) -> dict:
    """Full Certificate Transparency scan for a domain."""
    print_section("Certificate Transparency Monitor")
    results = {
        "domain": domain,
        "subdomains": [],
        "resolved": {},
        "new_certs": [],
        "analysis": {},
    }

    console.print(f"[bold]Target:[/bold] {domain}\n")

    # ── Step 1: Collect from all CT sources ──
    console.print("[bold]Step 1:[/bold] Querying CT Log Sources\n")

    all_certs = []
    seen_subs = set()

    sources = [
        ("crt.sh", lambda: _search_crtsh(domain)),
        ("Cert Spotter", lambda: _search_certspotter(domain)),
        ("Censys Certs", lambda: _search_censys_certs(domain)),
        ("Google CT", lambda: _search_google_ct(domain)),
    ]

    for name, fn in sources:
        console.print(f"  [dim]Querying {name}...[/dim]")
        try:
            certs = fn()
            new_count = 0
            for cert in certs:
                sub = cert["subdomain"]
                if sub not in seen_subs:
                    seen_subs.add(sub)
                    all_certs.append(cert)
                    new_count += 1
            if certs:
                print_found(name, f"{len(certs)} cert(s), {new_count} unique new subdomain(s)")
            else:
                print_not_found(f"{name} — no results")
        except Exception as e:
            print_error(f"{name}: {e}")

    results["subdomains"] = all_certs
    console.print(f"\n  [bold cyan]Total unique subdomains: {len(all_certs)}[/bold cyan]\n")

    # ── Step 2: Show subdomain table ──
    if all_certs:
        table = create_table("Discovered Subdomains (CT Logs)", [
            ("#", "dim"), ("Subdomain", "cyan"), ("Issuer", "dim"), ("Issued", "green"), ("Expires", "yellow"),
        ])
        for i, cert in enumerate(sorted(all_certs, key=lambda x: x["subdomain"])[:100], 1):
            table.add_row(
                str(i),
                cert["subdomain"],
                cert.get("issuer", "-")[:40],
                cert.get("not_before", "-")[:10],
                cert.get("not_after", "-")[:10],
            )
        console.print(table)

        if len(all_certs) > 100:
            console.print(f"  [dim]... showing 100 of {len(all_certs)} subdomains[/dim]")

    # ── Step 3: New certificates (last 24h) ──
    console.print("\n[bold]Step 3:[/bold] Recently Issued Certificates (24h)\n")
    new_certs = _detect_new_certs(domain, since_hours=24)
    results["new_certs"] = new_certs

    if new_certs:
        console.print(f"  [bold yellow]Found {len(new_certs)} certificate(s) issued in the last 24 hours![/bold yellow]\n")
        for cert in new_certs[:20]:
            hrs = cert.get("age_hours", "?")
            console.print(f"    [yellow]NEW[/yellow] {cert['subdomain']} — issued {hrs}h ago")
    else:
        print_info("No new certificates in the last 24 hours")

    # ── Step 4: DNS Resolution ──
    if resolve and all_certs:
        console.print(f"\n[bold]Step 4:[/bold] Resolving {min(len(all_certs), 200)} subdomains\n")
        to_resolve = all_certs[:200]  # Cap at 200 to avoid hammering DNS
        resolved = _resolve_subdomains(to_resolve)
        results["resolved"] = resolved

        if resolved:
            res_table = create_table("Resolved Subdomains", [
                ("Subdomain", "cyan"), ("IP Address", "green"),
            ])
            for sub, ip in sorted(resolved.items()):
                res_table.add_row(sub, ip)
            console.print(res_table)
            print_found("Resolved", f"{len(resolved)}/{len(to_resolve)} subdomains have DNS records")

            # Unique IPs
            unique_ips = set(resolved.values())
            console.print(f"  [dim]Unique IP addresses: {len(unique_ips)}[/dim]")
        else:
            print_not_found("No subdomains could be resolved")

    # ── Step 5: Certificate Analysis ──
    console.print("\n[bold]Step 5:[/bold] Certificate Analysis\n")
    analysis = _analyze_certs(all_certs)
    results["analysis"] = analysis

    # Wildcards
    if analysis["wildcard_certs"]:
        console.print(f"  [yellow]Wildcard certificates: {len(analysis['wildcard_certs'])}[/yellow]")
        for wc in analysis["wildcard_certs"][:10]:
            console.print(f"    [yellow]•[/yellow] {wc}")

    # Top issuers
    if analysis["issuers"]:
        issuer_table = create_table("Certificate Issuers", [
            ("Issuer", "white"), ("Count", "cyan"),
        ])
        for issuer, count in sorted(analysis["issuers"].items(), key=lambda x: -x[1])[:10]:
            issuer_table.add_row(issuer[:50], str(count))
        console.print(issuer_table)

    # Expiring soon
    if analysis["expiring_soon"]:
        console.print(f"\n  [bold red]Expiring within 30 days: {len(analysis['expiring_soon'])}[/bold red]")
        for exp in analysis["expiring_soon"][:10]:
            console.print(f"    [red]⚠[/red] {exp['subdomain']} — expires {exp['expires']} ({exp['days_left']}d left)")

    # ── Summary ──
    console.print(f"\n[bold green]CT Monitor complete — {len(all_certs)} subdomains, "
                  f"{len(new_certs)} new (24h), "
                  f"{len(results.get('resolved', {}))} resolved[/bold green]")

    return results


def ct_watch(domain: str, interval_minutes: int = 60, max_checks: int = 24):
    """Continuous CT log monitoring (polling mode)."""
    print_section("CT Log Watch Mode")
    console.print(f"[bold]Monitoring:[/bold] {domain}")
    console.print(f"[bold]Interval:[/bold] {interval_minutes} minutes")
    console.print(f"[bold]Max checks:[/bold] {max_checks}\n")

    known_subs = set()
    check_count = 0

    while check_count < max_checks:
        check_count += 1
        console.print(f"\n[bold cyan]Check #{check_count}[/bold cyan] — {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")

        certs = _search_crtsh(domain, recent_days=1)
        new_finds = []

        for cert in certs:
            sub = cert["subdomain"]
            if sub not in known_subs:
                known_subs.add(sub)
                new_finds.append(cert)

        if new_finds:
            console.print(f"  [bold yellow]New subdomains found: {len(new_finds)}[/bold yellow]")
            for cert in new_finds:
                ip = resolve_host(cert["subdomain"])
                ip_str = f" → {ip}" if ip else ""
                console.print(f"    [yellow]NEW[/yellow] {cert['subdomain']}{ip_str}")
        else:
            console.print(f"  [dim]No new subdomains (total known: {len(known_subs)})[/dim]")

        if check_count < max_checks:
            console.print(f"  [dim]Next check in {interval_minutes} minutes...[/dim]")
            time.sleep(interval_minutes * 60)

    console.print(f"\n[bold green]Watch complete — {len(known_subs)} total subdomains discovered[/bold green]")
