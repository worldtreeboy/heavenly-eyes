"""Dark Web Monitor — IntelligenceX, Dehashed, breach paste monitoring."""

import json
import hashlib
import time
from heavenlyeyes.core.utils import (
    console, make_request, print_section, print_found, print_not_found,
    print_info, print_warning, print_error, create_table,
)
from heavenlyeyes.core.config import get_api_key

# ── IntelligenceX API ─────────────────────────────────────────────────

INTELX_BASE = "https://2.intelx.io"


def _intelx_search(query: str, max_results: int = 20) -> list:
    """Search IntelligenceX for dark web mentions."""
    api_key = get_api_key("intelx")
    if not api_key:
        return []

    headers = {"x-key": api_key, "Content-Type": "application/json"}

    # Start search
    payload = {
        "term": query,
        "maxresults": max_results,
        "media": 0,  # all media types
        "sort": 2,   # date descending
        "timeout": 10,
    }

    resp = make_request(
        f"{INTELX_BASE}/intelligent/search",
        method="POST",
        headers=headers,
        json=payload,
    )

    if not resp or resp.status_code != 200:
        return []

    search_id = resp.json().get("id")
    if not search_id:
        return []

    # Poll for results
    time.sleep(2)
    results_resp = make_request(
        f"{INTELX_BASE}/intelligent/search/result?id={search_id}&limit={max_results}",
        headers=headers,
    )

    if not results_resp or results_resp.status_code != 200:
        return []

    records = results_resp.json().get("records", [])
    results = []
    for rec in records:
        results.append({
            "source": "IntelligenceX",
            "name": rec.get("name", "Unknown"),
            "date": rec.get("date", "Unknown"),
            "type": _intelx_media_type(rec.get("media", 0)),
            "bucket": rec.get("bucket", ""),
            "size": rec.get("storageid", ""),
        })

    return results


def _intelx_media_type(media_id: int) -> str:
    """Convert IntelX media type ID to human readable."""
    types = {
        0: "All", 1: "Paste", 2: "Paste (document)", 3: "Forum",
        4: "Forum (board)", 5: "URL", 6: "URL (document)",
        7: "Data Leak", 13: "Darknet", 14: "Darknet (document)",
        18: "Whois", 23: "Public Data Leak",
    }
    return types.get(media_id, f"Type_{media_id}")


# ── Dehashed API ──────────────────────────────────────────────────────

def _dehashed_search(query: str, query_type: str = "email") -> list:
    """Search Dehashed for breached credentials."""
    api_key = get_api_key("dehashed")
    email = get_api_key("dehashed_email")  # Dehashed requires email + API key auth
    if not api_key or not email:
        return []

    headers = {"Accept": "application/json"}
    resp = make_request(
        f"https://api.dehashed.com/search?query={query_type}:{query}&size=50",
        headers=headers,
        auth=(email, api_key),
    )

    if not resp or resp.status_code != 200:
        return []

    data = resp.json()
    entries = data.get("entries", []) or []
    results = []

    for entry in entries[:50]:
        result = {"source": "Dehashed"}
        if entry.get("email"):
            result["email"] = entry["email"]
        if entry.get("username"):
            result["username"] = entry["username"]
        if entry.get("password"):
            result["password_hash"] = entry["password"][:8] + "***"
        if entry.get("hashed_password"):
            result["hashed_password"] = entry["hashed_password"][:12] + "..."
        if entry.get("name"):
            result["name"] = entry["name"]
        if entry.get("database_name"):
            result["database"] = entry["database_name"]
        if entry.get("ip_address"):
            result["ip"] = entry["ip_address"]
        results.append(result)

    return results


# ── LeakLookup API ────────────────────────────────────────────────────

def _leaklookup_search(query: str, query_type: str = "email_address") -> list:
    """Search LeakLookup for breached data."""
    api_key = get_api_key("leaklookup")
    if not api_key:
        return []

    resp = make_request(
        "https://leak-lookup.com/api/search",
        method="POST",
        data={"key": api_key, "type": query_type, "query": query},
    )

    if not resp or resp.status_code != 200:
        return []

    data = resp.json()
    if not data.get("error") == "false":
        return []

    results = []
    for db_name, entries in (data.get("message", {}) or {}).items():
        if isinstance(entries, list):
            for entry in entries[:10]:
                results.append({
                    "source": "LeakLookup",
                    "database": db_name,
                    "data": str(entry)[:100],
                })
        elif isinstance(entries, dict):
            results.append({
                "source": "LeakLookup",
                "database": db_name,
                "data": str(entries)[:100],
            })

    return results


# ── Free / No-Key Sources ─────────────────────────────────────────────

def _haveibeenzapped(query: str) -> list:
    """Check HaveIBeenPwned free breach list."""
    results = []

    # Check HIBP breaches (free endpoint for domain breaches)
    if "@" in query:
        # Email - needs API key
        api_key = get_api_key("haveibeenpwned")
        if api_key:
            headers = {"hibp-api-key": api_key, "User-Agent": "HeavenlyEyes-OSINT"}
            resp = make_request(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{query}",
                headers=headers,
            )
            if resp and resp.status_code == 200:
                for breach in resp.json():
                    results.append({
                        "source": "HIBP",
                        "database": breach.get("Name", "Unknown"),
                        "date": breach.get("BreachDate", "Unknown"),
                        "count": breach.get("PwnCount", 0),
                        "data_types": ", ".join(breach.get("DataClasses", [])[:5]),
                    })
    else:
        # Domain - check free breach list
        resp = make_request("https://haveibeenpwned.com/api/v3/breaches")
        if resp and resp.status_code == 200:
            for breach in resp.json():
                domain = breach.get("Domain", "").lower()
                if query.lower() in domain:
                    results.append({
                        "source": "HIBP",
                        "database": breach.get("Name", "Unknown"),
                        "date": breach.get("BreachDate", "Unknown"),
                        "count": breach.get("PwnCount", 0),
                        "data_types": ", ".join(breach.get("DataClasses", [])[:5]),
                    })

    return results


def _xposedornot(email: str) -> list:
    """Check XposedOrNot (free, no key needed)."""
    results = []
    resp = make_request(f"https://api.xposedornot.com/v1/check-email/{email}")
    if resp and resp.status_code == 200:
        data = resp.json()
        breaches = data.get("breaches", [])
        if isinstance(breaches, list):
            for b in breaches:
                results.append({
                    "source": "XposedOrNot",
                    "database": b if isinstance(b, str) else str(b),
                })
    return results


def _check_paste_sites(query: str) -> list:
    """Generate paste site search URLs."""
    results = []
    sites = [
        ("Pastebin", f"https://pastebin.com/search?q={query}"),
        ("GitHub Code", f"https://github.com/search?q=%22{query}%22&type=code"),
        ("GitLab", f"https://gitlab.com/search?search={query}&nav_source=navbar"),
        ("Ghostbin", f"https://ghostbin.me/search?q={query}"),
        ("Rentry", f"https://rentry.org/search?q={query}"),
    ]

    for name, url in sites:
        results.append({
            "source": name,
            "url": url,
            "note": "Manual search — check for exposed data",
        })

    return results


def _check_breach_directory(query: str) -> list:
    """Check free breach compilation directories."""
    results = []

    # BreachDirectory (free tier)
    resp = make_request(
        f"https://breachdirectory.p.rapidapi.com/?func=auto&term={query}",
        headers={
            "X-RapidAPI-Key": get_api_key("rapidapi") or "",
            "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
        },
    )
    if resp and resp.status_code == 200:
        data = resp.json()
        if data.get("success") and data.get("result"):
            for entry in data["result"][:20]:
                results.append({
                    "source": "BreachDirectory",
                    "email": entry.get("email", ""),
                    "password_hash": (entry.get("password", "") or "")[:8] + "***" if entry.get("password") else "",
                    "sha1": entry.get("sha1", "")[:12] + "..." if entry.get("sha1") else "",
                    "sources": entry.get("sources", ""),
                })

    return results


# ════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ════════════════════════════════════════════════════════════════════════

def darkweb_scan(query: str, query_type: str = "auto") -> dict:
    """Full dark web and breach monitoring scan."""
    print_section("Dark Web Monitor")
    results = {
        "query": query,
        "intelx": [],
        "dehashed": [],
        "leaklookup": [],
        "hibp": [],
        "xposed": [],
        "breach_directory": [],
        "paste_sites": [],
    }

    # Auto-detect query type
    if query_type == "auto":
        if "@" in query:
            query_type = "email"
        elif "." in query and not query.replace(".", "").isdigit():
            query_type = "domain"
        else:
            query_type = "username"

    console.print(f"[bold]Target:[/bold] {query}  [dim]({query_type})[/dim]\n")

    # ── Step 1: IntelligenceX (Dark Web + Paste) ──
    console.print("[bold]Step 1:[/bold] IntelligenceX (Dark Web, Pastes, Leaks)\n")
    if get_api_key("intelx"):
        console.print("  [dim]Searching IntelligenceX...[/dim]")
        intelx = _intelx_search(query)
        results["intelx"] = intelx
        if intelx:
            table = create_table("IntelligenceX Results", [
                ("Type", "red"), ("Name", "white"), ("Date", "dim"),
            ])
            for r in intelx[:15]:
                table.add_row(r["type"], r["name"][:60], r["date"][:10])
            console.print(table)
            print_found("IntelligenceX", f"{len(intelx)} result(s)")
        else:
            print_not_found("IntelligenceX — no results")
    else:
        print_warning("IntelligenceX — no API key (set HEYES_INTELX)")

    # ── Step 2: Dehashed (Breached Credentials) ──
    console.print("\n[bold]Step 2:[/bold] Dehashed (Breached Credentials)\n")
    if get_api_key("dehashed"):
        console.print("  [dim]Searching Dehashed...[/dim]")
        dehashed_type = query_type if query_type in ("email", "domain", "username") else "email"
        dehashed = _dehashed_search(query, dehashed_type)
        results["dehashed"] = dehashed
        if dehashed:
            table = create_table("Dehashed Results", [
                ("Database", "red"), ("Email", "white"),
                ("Username", "cyan"), ("Password", "yellow"),
            ])
            for r in dehashed[:15]:
                table.add_row(
                    r.get("database", "-"), r.get("email", "-"),
                    r.get("username", "-"), r.get("password_hash", "-"),
                )
            console.print(table)
            print_found("Dehashed", f"{len(dehashed)} breached record(s)")
        else:
            print_not_found("Dehashed — no results")
    else:
        print_warning("Dehashed — no API key (set HEYES_DEHASHED)")

    # ── Step 3: LeakLookup ──
    console.print("\n[bold]Step 3:[/bold] LeakLookup\n")
    if get_api_key("leaklookup"):
        console.print("  [dim]Searching LeakLookup...[/dim]")
        ll_type = "email_address" if query_type == "email" else "domain" if query_type == "domain" else "username"
        leaklookup = _leaklookup_search(query, ll_type)
        results["leaklookup"] = leaklookup
        if leaklookup:
            print_found("LeakLookup", f"{len(leaklookup)} result(s) across {len(set(r['database'] for r in leaklookup))} database(s)")
            for r in leaklookup[:10]:
                console.print(f"    [red]•[/red] {r['database']}: {r['data'][:60]}")
        else:
            print_not_found("LeakLookup — no results")
    else:
        print_warning("LeakLookup — no API key (set HEYES_LEAKLOOKUP)")

    # ── Step 4: HIBP (Free Breach Check) ──
    console.print("\n[bold]Step 4:[/bold] Have I Been Pwned\n")
    console.print("  [dim]Checking HIBP...[/dim]")
    hibp = _haveibeenzapped(query)
    results["hibp"] = hibp
    if hibp:
        table = create_table("HIBP Breaches", [
            ("Breach", "red"), ("Date", "dim"), ("Records", "yellow"), ("Data Types", "white"),
        ])
        for r in hibp[:15]:
            table.add_row(r["database"], r["date"], f"{r['count']:,}", r["data_types"])
        console.print(table)
        print_found("HIBP", f"{len(hibp)} breach(es)")
    else:
        print_not_found("HIBP — no breaches found")

    # ── Step 5: XposedOrNot (Free) ──
    if query_type == "email":
        console.print("\n[bold]Step 5:[/bold] XposedOrNot (Free)\n")
        console.print("  [dim]Checking XposedOrNot...[/dim]")
        xposed = _xposedornot(query)
        results["xposed"] = xposed
        if xposed:
            print_found("XposedOrNot", f"{len(xposed)} breach(es)")
            for r in xposed[:10]:
                console.print(f"    [red]•[/red] {r['database']}")
        else:
            print_not_found("XposedOrNot — no results")

    # ── Step 6: Breach Directory ──
    console.print("\n[bold]Step 6:[/bold] Breach Directory\n")
    console.print("  [dim]Checking Breach Directory...[/dim]")
    bd = _check_breach_directory(query)
    results["breach_directory"] = bd
    if bd:
        print_found("BreachDirectory", f"{len(bd)} record(s)")
    else:
        print_not_found("BreachDirectory — no results")

    # ── Step 7: Paste Sites (Manual Lookup URLs) ──
    console.print("\n[bold]Step 7:[/bold] Paste Site Monitoring\n")
    pastes = _check_paste_sites(query)
    results["paste_sites"] = pastes
    table = create_table("Paste Site Search URLs", [
        ("Site", "cyan"), ("URL", "white"),
    ])
    for p in pastes:
        table.add_row(p["source"], p["url"])
    console.print(table)

    # ── Summary ──
    total = sum(len(v) for v in results.values() if isinstance(v, list))
    breached_sources = sum(1 for k in ["intelx", "dehashed", "leaklookup", "hibp", "xposed", "breach_directory"]
                          if results.get(k))

    if total > 0:
        console.print(f"\n[bold red]ALERT: {total} total records found across {breached_sources} source(s)[/bold red]")
    else:
        console.print(f"\n[bold green]No dark web exposure detected[/bold green]")

    return results
