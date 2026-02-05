"""Email reconnaissance — validation, pattern generation, breach checking."""

import re
import dns.resolver
from heavenlyeyes.core.utils import (
    print_section, print_found, print_not_found, print_info, print_warning,
    print_error, create_table, console, make_request,
)
from heavenlyeyes.core.config import get_api_key


# ── Email Validation ───────────────────────────────────────────────────

def validate_email(email: str) -> dict:
    """Validate an email address via MX record and format check."""
    print_section("Email Validation")

    result = {
        "email": email,
        "format_valid": False,
        "mx_exists": False,
        "mx_records": [],
    }

    # Format check
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    result["format_valid"] = bool(re.match(pattern, email))
    if result["format_valid"]:
        print_found("Format", "Valid email format")
    else:
        print_error("Invalid email format")
        return result

    # MX record check
    domain = email.split("@")[1]
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        result["mx_exists"] = True
        result["mx_records"] = [str(r.exchange) for r in mx_records]
        for mx in result["mx_records"]:
            print_found("MX Record", mx)
    except Exception:
        print_not_found("MX Records")

    return result


# ── Email Pattern Generation ──────────────────────────────────────────

def generate_patterns(first: str, last: str, domain: str) -> list[str]:
    """Generate common email patterns for a person at a domain."""
    print_section("Email Pattern Generation")

    f = first.lower().strip()
    l = last.lower().strip()
    fi = f[0] if f else ""
    li = l[0] if l else ""

    patterns = [
        f"{f}@{domain}",
        f"{l}@{domain}",
        f"{f}.{l}@{domain}",
        f"{f}{l}@{domain}",
        f"{fi}{l}@{domain}",
        f"{f}{li}@{domain}",
        f"{fi}.{l}@{domain}",
        f"{f}.{li}@{domain}",
        f"{l}.{f}@{domain}",
        f"{l}{f}@{domain}",
        f"{l}{fi}@{domain}",
        f"{f}_{l}@{domain}",
        f"{f}-{l}@{domain}",
        f"{fi}{l}@{domain}",
    ]

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    table = create_table(
        f"Email Patterns for {first} {last} @ {domain}",
        [("#", "dim"), ("Email Pattern", "green")],
    )
    for i, p in enumerate(unique, 1):
        table.add_row(str(i), p)

    console.print(table)
    return unique


# ── Breach Check ──────────────────────────────────────────────────────

def check_breaches(email: str) -> dict:
    """Check if an email has been in known breaches using HaveIBeenPwned API."""
    print_section("Breach Check")

    api_key = get_api_key("haveibeenpwned")

    if not api_key:
        print_warning(
            "No HIBP API key configured. Set HEYES_HAVEIBEENPWNED env var or add to ~/.heavenlyeyes/config.yaml"
        )
        print_info("Attempting free breach check via alternative method...")
        return _free_breach_check(email)

    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "HeavenlyEyes-OSINT",
    }
    resp = make_request(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers=headers,
    )

    result = {"email": email, "breached": False, "breaches": []}

    if resp and resp.status_code == 200:
        breaches = resp.json()
        result["breached"] = True
        result["breaches"] = breaches

        table = create_table(
            f"Breaches for {email}",
            [("Breach", "red"), ("Date", "white"), ("Data Types", "dim")],
        )
        for b in breaches:
            table.add_row(
                b.get("Name", "Unknown"),
                b.get("BreachDate", "Unknown"),
                ", ".join(b.get("DataClasses", [])),
            )
        console.print(table)
        print_warning(f"Found in {len(breaches)} breach(es)!")

    elif resp and resp.status_code == 404:
        print_found("Status", "Not found in any known breaches")
    else:
        print_error("Could not check breaches")

    return result


def _free_breach_check(email: str) -> dict:
    """Fallback breach check using free services."""
    result = {"email": email, "breached": False, "sources": []}

    # Check via breach directory (no API key needed)
    resp = make_request(f"https://api.xposedornot.com/v1/check-email/{email}")
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if data.get("breaches"):
                result["breached"] = True
                result["sources"] = data["breaches"]
                print_warning(f"Email found in breach databases!")
                for src in data["breaches"][:10]:
                    print_found("Breach", str(src))
            else:
                print_found("Status", "Not found in checked breach databases")
        except Exception:
            print_info("Could not parse breach response")
    else:
        print_info("Free breach check unavailable — consider adding an HIBP API key")

    return result


# ── Email Harvesting ──────────────────────────────────────────────────

def harvest_emails(domain: str) -> list[str]:
    """Harvest emails from various public sources for a domain."""
    print_section("Email Harvesting")

    emails = set()

    # Search via web scraping of the domain itself
    for proto in ("https", "http"):
        for path in ("", "/about", "/contact", "/team", "/about-us", "/contact-us"):
            resp = make_request(f"{proto}://{domain}{path}")
            if resp:
                found = re.findall(
                    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                    resp.text,
                )
                emails.update(e.lower() for e in found if domain in e.lower())

    if emails:
        table = create_table(
            f"Harvested Emails for {domain}",
            [("#", "dim"), ("Email", "green")],
        )
        for i, email in enumerate(sorted(emails), 1):
            table.add_row(str(i), email)
        console.print(table)
        print_info(f"Found {len(emails)} email(s)")
    else:
        print_info("No emails harvested from public pages")

    return sorted(emails)
