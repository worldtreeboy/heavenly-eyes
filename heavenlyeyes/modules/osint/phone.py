"""Phone Number OSINT — carrier lookup, format validation, social account linking."""

import re
import json
from heavenlyeyes.core.utils import (
    console, make_request, print_section, print_found, print_not_found,
    print_info, print_warning, print_error, create_table,
)
from heavenlyeyes.core.config import get_api_key

# ── Phone number format patterns ──────────────────────────────────────

COUNTRY_CODES = {
    "1": "US/CA", "44": "GB", "86": "CN", "91": "IN", "81": "JP",
    "49": "DE", "33": "FR", "61": "AU", "55": "BR", "7": "RU",
    "82": "KR", "39": "IT", "34": "ES", "31": "NL", "46": "SE",
    "47": "NO", "45": "DK", "358": "FI", "48": "PL", "90": "TR",
    "52": "MX", "54": "AR", "57": "CO", "56": "CL", "66": "TH",
    "84": "VN", "62": "ID", "60": "MY", "63": "PH", "65": "SG",
    "971": "AE", "966": "SA", "972": "IL", "20": "EG", "27": "ZA",
    "234": "NG", "254": "KE",
}

CARRIER_SIGNATURES = {
    "US/CA": {
        "ranges": {
            "201-299": "Various",
            "301-399": "Various",
        },
        "major": ["AT&T", "Verizon", "T-Mobile", "Sprint"],
    },
}


def _normalize_phone(phone: str) -> str:
    """Strip a phone number to digits only, keeping leading +."""
    has_plus = phone.strip().startswith("+")
    digits = re.sub(r"[^\d]", "", phone)
    return f"+{digits}" if has_plus else digits


def _detect_country(phone: str) -> dict:
    """Detect country from phone number."""
    digits = re.sub(r"[^\d]", "", phone)

    # Try 3-digit, 2-digit, 1-digit country codes
    for length in (3, 2, 1):
        code = digits[:length]
        if code in COUNTRY_CODES:
            return {
                "country_code": f"+{code}",
                "country": COUNTRY_CODES[code],
                "national_number": digits[length:],
            }

    return {"country_code": "Unknown", "country": "Unknown", "national_number": digits}


def _validate_format(phone: str) -> dict:
    """Validate phone number format and extract metadata."""
    normalized = _normalize_phone(phone)
    digits = re.sub(r"[^\d]", "", normalized)

    result = {
        "input": phone,
        "normalized": normalized,
        "digits_only": digits,
        "digit_count": len(digits),
        "valid_length": 7 <= len(digits) <= 15,
    }

    country_info = _detect_country(normalized)
    result.update(country_info)

    # Detect format type
    if re.match(r"^\+\d{1,3}\d{6,14}$", normalized):
        result["format"] = "E.164 (International)"
    elif re.match(r"^0\d{9,10}$", digits):
        result["format"] = "National (with trunk prefix)"
    else:
        result["format"] = "Unknown / Local"

    return result


# ── API Lookups ───────────────────────────────────────────────────────

def _numverify_lookup(phone: str) -> dict | None:
    """Lookup via NumVerify API."""
    api_key = get_api_key("numverify")
    if not api_key:
        return None

    resp = make_request(
        f"http://apilayer.net/api/validate?access_key={api_key}&number={phone}&format=1"
    )
    if resp and resp.status_code == 200:
        data = resp.json()
        if data.get("valid"):
            return {
                "valid": data.get("valid"),
                "country": data.get("country_name"),
                "location": data.get("location"),
                "carrier": data.get("carrier"),
                "line_type": data.get("line_type"),
            }
    return None


def _abstractapi_lookup(phone: str) -> dict | None:
    """Lookup via AbstractAPI Phone Validation."""
    api_key = get_api_key("abstractapi_phone")
    if not api_key:
        return None

    resp = make_request(
        f"https://phonevalidation.abstractapi.com/v1/?api_key={api_key}&phone={phone}"
    )
    if resp and resp.status_code == 200:
        data = resp.json()
        if data.get("valid"):
            return {
                "valid": data.get("valid"),
                "country": data.get("country", {}).get("name"),
                "carrier": data.get("carrier"),
                "type": data.get("type"),
                "format_international": data.get("format", {}).get("international"),
            }
    return None


def _veriphone_lookup(phone: str) -> dict | None:
    """Free lookup via Veriphone API (no key needed for basic)."""
    resp = make_request(f"https://api.veriphone.io/v2/verify?phone={phone}")
    if resp and resp.status_code == 200:
        data = resp.json()
        if data.get("phone_valid"):
            return {
                "valid": True,
                "country": data.get("country"),
                "country_code": data.get("country_code"),
                "carrier": data.get("carrier"),
                "type": data.get("phone_type"),
                "international": data.get("international_number"),
            }
    return None


# ── Social Account Discovery ─────────────────────────────────────────

SOCIAL_PHONE_CHECKS = [
    {
        "name": "Telegram",
        "method": "telegram_check",
    },
    {
        "name": "WhatsApp",
        "method": "whatsapp_check",
    },
    {
        "name": "Truecaller",
        "method": "truecaller_check",
    },
    {
        "name": "Sync.me",
        "method": "syncme_check",
    },
]


def _check_telegram(phone: str) -> dict | None:
    """Check if phone is registered on Telegram via public resolver."""
    # Uses t.me redirect behavior
    normalized = _normalize_phone(phone)
    if not normalized.startswith("+"):
        normalized = f"+{normalized}"

    resp = make_request(
        f"https://t.me/{normalized}",
        allow_redirects=False,
    )
    if resp:
        if resp.status_code == 200 or "tgme_page" in resp.text[:500]:
            return {"platform": "Telegram", "registered": True, "phone": normalized}
    return None


def _check_whatsapp(phone: str) -> dict | None:
    """Check WhatsApp presence via wa.me link behavior."""
    normalized = re.sub(r"[^\d]", "", phone)
    resp = make_request(f"https://wa.me/{normalized}", allow_redirects=False)
    if resp:
        # wa.me returns 200 with a form if the number exists
        if resp.status_code == 200 and "send a message" in resp.text.lower()[:1000]:
            return {"platform": "WhatsApp", "registered": True, "phone": f"+{normalized}"}
        elif resp.status_code in (301, 302):
            location = resp.headers.get("location", "")
            if "send" in location.lower():
                return {"platform": "WhatsApp", "registered": True, "phone": f"+{normalized}"}
    return None


def _check_callerid_services(phone: str) -> list:
    """Check various caller ID / reverse lookup services."""
    results = []
    normalized = re.sub(r"[^\d]", "", phone)

    # SpyDialer (US only, no API key needed)
    if len(normalized) == 10 or (len(normalized) == 11 and normalized.startswith("1")):
        results.append({
            "service": "SpyDialer",
            "url": f"https://www.spydialer.com/results.aspx?Number={normalized}",
            "note": "Manual lookup — free reverse phone",
        })

    # ThatsThem
    results.append({
        "service": "ThatsThem",
        "url": f"https://thatsthem.com/reverse-phone-lookup/{normalized}",
        "note": "Reverse phone lookup — name, address, email",
    })

    # TruePeopleSearch (US)
    results.append({
        "service": "TruePeopleSearch",
        "url": f"https://www.truepeoplesearch.com/results?phoneno={normalized}",
        "note": "Free people search — US numbers",
    })

    # NumLookup
    resp = make_request(f"https://www.numlookup.com/api/validate/{normalized}")
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if data.get("valid"):
                results.append({
                    "service": "NumLookup",
                    "carrier": data.get("carrier"),
                    "type": data.get("line_type"),
                    "country": data.get("country_name"),
                })
        except Exception:
            pass

    return results


# ── Google Dorking for Phone ──────────────────────────────────────────

def _generate_phone_dorks(phone: str) -> list:
    """Generate Google dorks for phone number recon."""
    normalized = _normalize_phone(phone)
    digits = re.sub(r"[^\d]", "", phone)

    # Generate multiple format variations
    formats = {normalized, digits, phone.strip()}

    # Add formatted versions
    if len(digits) == 10:
        formats.add(f"({digits[:3]}) {digits[3:6]}-{digits[6:]}")
        formats.add(f"{digits[:3]}-{digits[3:6]}-{digits[6:]}")
        formats.add(f"{digits[:3]}.{digits[3:6]}.{digits[6:]}")
    elif len(digits) == 11 and digits.startswith("1"):
        d = digits[1:]
        formats.add(f"+1 ({d[:3]}) {d[3:6]}-{d[6:]}")
        formats.add(f"1-{d[:3]}-{d[3:6]}-{d[6:]}")

    dorks = []
    for fmt in formats:
        dorks.append(f'"{fmt}"')
        dorks.append(f'"{fmt}" site:linkedin.com')
        dorks.append(f'"{fmt}" site:facebook.com')
        dorks.append(f'"{fmt}" filetype:pdf')
        dorks.append(f'"{fmt}" filetype:xlsx OR filetype:csv')
        dorks.append(f'"{fmt}" inurl:contact')

    return list(set(dorks))


# ════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ════════════════════════════════════════════════════════════════════════

def phone_lookup(phone: str) -> dict:
    """Full phone number OSINT scan."""
    print_section("Phone Number OSINT")
    results = {"phone": phone, "format_analysis": {}, "api_lookups": [], "social": [], "dorks": []}

    # ── Step 1: Format analysis ──
    console.print("[bold]Step 1:[/bold] Format Analysis\n")
    fmt = _validate_format(phone)
    results["format_analysis"] = fmt

    if fmt["valid_length"]:
        print_found("Format", fmt.get("format", "Unknown"))
        print_found("Country", f"{fmt.get('country', '?')} ({fmt.get('country_code', '?')})")
        print_found("National Number", fmt.get("national_number", "?"))
        print_found("Digit Count", str(fmt["digit_count"]))
    else:
        print_error(f"Invalid phone number length: {fmt['digit_count']} digits")

    # ── Step 2: API Lookups ──
    console.print("\n[bold]Step 2:[/bold] Carrier & Validation Lookups\n")

    for name, fn in [("NumVerify", _numverify_lookup), ("AbstractAPI", _abstractapi_lookup), ("Veriphone", _veriphone_lookup)]:
        console.print(f"  [dim]Checking {name}...[/dim]")
        try:
            data = fn(phone)
            if data:
                results["api_lookups"].append({"source": name, **data})
                print_found(name, f"Carrier: {data.get('carrier', '?')} | Type: {data.get('type') or data.get('line_type', '?')}")
            else:
                print_not_found(name)
        except Exception as e:
            print_error(f"{name}: {e}")

    # ── Step 3: Social / Messaging Platforms ──
    console.print("\n[bold]Step 3:[/bold] Social Platform Checks\n")

    console.print("  [dim]Checking Telegram...[/dim]")
    try:
        tg = _check_telegram(phone)
        if tg:
            results["social"].append(tg)
            print_found("Telegram", "Registered")
        else:
            print_not_found("Telegram")
    except Exception:
        print_not_found("Telegram")

    console.print("  [dim]Checking WhatsApp...[/dim]")
    try:
        wa = _check_whatsapp(phone)
        if wa:
            results["social"].append(wa)
            print_found("WhatsApp", "Registered")
        else:
            print_not_found("WhatsApp")
    except Exception:
        print_not_found("WhatsApp")

    # ── Step 4: Caller ID / Reverse Lookup ──
    console.print("\n[bold]Step 4:[/bold] Reverse Lookup Services\n")
    callerid = _check_callerid_services(phone)
    results["reverse_lookups"] = callerid

    table = create_table("Reverse Lookup Services", [
        ("Service", "cyan"),
        ("Info", "white"),
        ("URL", "dim"),
    ])
    for svc in callerid:
        info = svc.get("carrier") or svc.get("note", "")
        url = svc.get("url", "-")
        table.add_row(svc["service"], info, url)

    if callerid:
        console.print(table)
    else:
        print_not_found("No reverse lookup results")

    # ── Step 5: Google Dorks ──
    console.print("\n[bold]Step 5:[/bold] OSINT Dorks\n")
    dorks = _generate_phone_dorks(phone)
    results["dorks"] = dorks

    dork_table = create_table("Phone Number Dorks", [("#", "dim"), ("Query", "white")])
    for i, d in enumerate(dorks[:15], 1):
        dork_table.add_row(str(i), d)
    console.print(dork_table)

    if len(dorks) > 15:
        console.print(f"  [dim]... and {len(dorks) - 15} more dorks[/dim]")

    # ── Summary ──
    total = len(results["api_lookups"]) + len(results["social"]) + len(callerid)
    console.print(f"\n[bold green]Phone OSINT complete — {total} data points collected[/bold green]")

    return results
