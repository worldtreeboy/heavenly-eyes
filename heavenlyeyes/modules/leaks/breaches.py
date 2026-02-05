"""Leaked information — breach databases, paste sites, archives."""

import re
from heavenlyeyes.core.utils import (
    print_section, print_found, print_not_found, print_info, print_warning,
    print_error, create_table, console, make_request,
)
from heavenlyeyes.core.config import get_api_key


# ── Breach Database Check ──────────────────────────────────────────────

def check_domain_breaches(domain: str) -> dict:
    """Check if a domain has been involved in known breaches."""
    print_section("Domain Breach Check")

    result = {"domain": domain, "breaches": []}

    api_key = get_api_key("haveibeenpwned")
    if api_key:
        resp = make_request(
            f"https://haveibeenpwned.com/api/v3/breaches",
            headers={"hibp-api-key": api_key},
        )
        if resp and resp.status_code == 200:
            all_breaches = resp.json()
            domain_breaches = [
                b for b in all_breaches
                if domain.lower() in b.get("Domain", "").lower()
            ]
            if domain_breaches:
                result["breaches"] = domain_breaches
                table = create_table(
                    f"Breaches involving {domain}",
                    [("Name", "red"), ("Date", "white"), ("Records", "yellow"), ("Data Types", "dim")],
                )
                for b in domain_breaches:
                    table.add_row(
                        b["Name"],
                        b.get("BreachDate", "?"),
                        str(b.get("PwnCount", "?")),
                        ", ".join(b.get("DataClasses", [])[:5]),
                    )
                console.print(table)
                print_warning(f"Domain found in {len(domain_breaches)} breach(es)")
            else:
                print_found("Status", "Domain not found in HIBP breach database")
    else:
        print_info("No HIBP API key — using alternative breach check")
        result = _alt_domain_breach_check(domain)

    return result


def _alt_domain_breach_check(domain: str) -> dict:
    """Alternative breach check without API key."""
    result = {"domain": domain, "breaches": []}

    # Check via XposedOrNot
    resp = make_request(f"https://api.xposedornot.com/v1/domain-breaches/?domain={domain}")
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if data.get("exposures") or data.get("breaches"):
                breaches = data.get("exposures", data.get("breaches", []))
                result["breaches"] = breaches
                print_warning(f"Domain appears in breach databases")
                if isinstance(breaches, list):
                    for b in breaches[:10]:
                        print_found("Breach", str(b))
            else:
                print_found("Status", "Not found in checked breach databases")
        except Exception:
            pass
    else:
        print_info("Alternative breach check unavailable")

    return result


# ── Archive Check ──────────────────────────────────────────────────────

def check_archives(domain: str) -> dict:
    """Check for archived versions of a domain via Wayback Machine."""
    print_section("Web Archive Check")

    result = {"domain": domain, "snapshots": [], "first_seen": None, "last_seen": None}

    # Wayback Machine CDX API
    resp = make_request(
        f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=20&fl=timestamp,statuscode,original&collapse=timestamp:6"
    )
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if len(data) > 1:  # First row is headers
                headers = data[0]
                snapshots = [dict(zip(headers, row)) for row in data[1:]]
                result["snapshots"] = snapshots

                if snapshots:
                    result["first_seen"] = snapshots[0].get("timestamp", "")
                    result["last_seen"] = snapshots[-1].get("timestamp", "")

                    table = create_table(
                        f"Wayback Machine Snapshots for {domain}",
                        [("Date", "cyan"), ("Status", "white"), ("URL", "dim")],
                    )
                    for s in snapshots:
                        ts = s.get("timestamp", "")
                        formatted = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
                        table.add_row(
                            formatted,
                            s.get("statuscode", "?"),
                            s.get("original", ""),
                        )
                    console.print(table)

                    print_info(f"Found {len(snapshots)} archived snapshots")
                    if result["first_seen"]:
                        ts = result["first_seen"]
                        print_found("First Archived", f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}")
            else:
                print_info("No archived snapshots found")
        except Exception as e:
            print_error(f"Error parsing archive data: {e}")
    else:
        print_info("Wayback Machine check unavailable")

    return result


# ── Internal Leak Indicators ──────────────────────────────────────────

def check_leak_indicators(domain: str) -> dict:
    """Check for indicators of internal leaks (exposed files, directories)."""
    print_section("Internal Leak Indicators")

    findings = {}

    sensitive_paths = [
        "/.env",
        "/.git/config",
        "/.git/HEAD",
        "/robots.txt",
        "/sitemap.xml",
        "/.htaccess",
        "/wp-config.php.bak",
        "/backup.sql",
        "/db.sql",
        "/dump.sql",
        "/config.php",
        "/config.yaml",
        "/config.json",
        "/.DS_Store",
        "/server-status",
        "/server-info",
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/admin/",
        "/administrator/",
        "/wp-admin/",
        "/login",
        "/api/",
        "/api/v1/",
        "/graphql",
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/.well-known/security.txt",
        "/security.txt",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/humans.txt",
    ]

    print_info(f"Checking {len(sensitive_paths)} sensitive paths...")

    for path in sensitive_paths:
        for proto in ("https", "http"):
            url = f"{proto}://{domain}{path}"
            try:
                import requests
                resp = requests.head(url, timeout=5, allow_redirects=False,
                                     headers={"User-Agent": "HeavenlyEyes/1.0"})
                if resp.status_code == 200:
                    findings[path] = {
                        "url": url,
                        "status": resp.status_code,
                        "size": resp.headers.get("Content-Length", "Unknown"),
                    }
                    severity = "red" if any(s in path for s in (".env", ".git", ".sql", "config", "phpinfo")) else "yellow"
                    print_found(f"[{severity}]EXPOSED[/{severity}]", f"{path} ({url})")
                    break
            except Exception:
                break

    if findings:
        print_warning(f"Found {len(findings)} exposed path(s) — review for sensitive data!")
    else:
        print_info("No sensitive paths exposed")

    return findings


# ── Paste Site Check ──────────────────────────────────────────────────

def check_pastes(query: str) -> dict:
    """Search for mentions on paste sites and public code repos."""
    print_section("Paste / Code Leak Search")

    results = {}

    # Search GitHub code (public API, no auth required for basic search)
    resp = make_request(
        f"https://api.github.com/search/code?q={query}&per_page=10",
        headers={"Accept": "application/vnd.github.v3+json"},
    )
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            items = data.get("items", [])
            if items:
                results["github_code"] = []
                table = create_table(
                    "GitHub Code Mentions",
                    [("Repository", "cyan"), ("File", "white"), ("URL", "dim")],
                )
                for item in items[:10]:
                    entry = {
                        "repo": item["repository"]["full_name"],
                        "path": item["path"],
                        "url": item["html_url"],
                    }
                    results["github_code"].append(entry)
                    table.add_row(entry["repo"], entry["path"], entry["url"])
                console.print(table)
                print_info(f"Found {data.get('total_count', len(items))} GitHub code mention(s)")
        except Exception:
            pass
    elif resp and resp.status_code == 403:
        print_info("GitHub API rate limit reached — try again later or add auth")

    if not results:
        print_info("No paste/code leak mentions found")

    return results
