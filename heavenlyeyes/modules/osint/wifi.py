"""WiFi Geolocation — WiGLE API for SSID mapping and wireless network intelligence."""

import re
import json
from heavenlyeyes.core.utils import (
    console, make_request, print_section, print_found, print_not_found,
    print_info, print_warning, print_error, create_table,
)
from heavenlyeyes.core.config import get_api_key

# ── WiGLE API ─────────────────────────────────────────────────────────

WIGLE_BASE = "https://api.wigle.net/api/v2"


def _wigle_headers() -> dict | None:
    """Get WiGLE API auth headers."""
    api_name = get_api_key("wigle_name")
    api_token = get_api_key("wigle_token")
    if not api_name or not api_token:
        return None
    return {"Authorization": f"Basic {_b64encode(api_name, api_token)}"}


def _b64encode(name: str, token: str) -> str:
    """Base64 encode credentials for WiGLE."""
    import base64
    return base64.b64encode(f"{name}:{token}".encode()).decode()


def _wigle_search_ssid(ssid: str, max_results: int = 100) -> list:
    """Search WiGLE for networks matching an SSID pattern."""
    headers = _wigle_headers()
    if not headers:
        return []

    resp = make_request(
        f"{WIGLE_BASE}/network/search?ssid={ssid}&resultsPerPage={max_results}",
        headers=headers,
        timeout=20,
    )

    if not resp or resp.status_code != 200:
        return []

    data = resp.json()
    results = []
    for net in data.get("results", []):
        results.append({
            "ssid": net.get("ssid", ""),
            "bssid": net.get("netid", ""),
            "encryption": net.get("encryption", "Unknown"),
            "channel": net.get("channel", 0),
            "latitude": net.get("trilat", 0),
            "longitude": net.get("trilong", 0),
            "city": net.get("city", ""),
            "region": net.get("region", ""),
            "country": net.get("country", ""),
            "last_seen": net.get("lastupdt", ""),
            "first_seen": net.get("firsttime", ""),
            "type": net.get("type", ""),
        })

    return results


def _wigle_search_location(lat: float, lon: float, radius_km: float = 0.5, max_results: int = 100) -> list:
    """Search WiGLE for networks near a location."""
    headers = _wigle_headers()
    if not headers:
        return []

    # Convert km to lat/lon delta (rough approximation)
    delta = radius_km / 111.0

    resp = make_request(
        f"{WIGLE_BASE}/network/search?"
        f"latrange1={lat - delta}&latrange2={lat + delta}"
        f"&longrange1={lon - delta}&longrange2={lon + delta}"
        f"&resultsPerPage={max_results}",
        headers=headers,
        timeout=20,
    )

    if not resp or resp.status_code != 200:
        return []

    data = resp.json()
    results = []
    for net in data.get("results", []):
        results.append({
            "ssid": net.get("ssid", ""),
            "bssid": net.get("netid", ""),
            "encryption": net.get("encryption", "Unknown"),
            "channel": net.get("channel", 0),
            "latitude": net.get("trilat", 0),
            "longitude": net.get("trilong", 0),
            "city": net.get("city", ""),
            "region": net.get("region", ""),
            "country": net.get("country", ""),
            "last_seen": net.get("lastupdt", ""),
            "type": net.get("type", ""),
        })

    return results


def _wigle_search_bssid(bssid: str) -> list:
    """Search WiGLE for a specific BSSID (MAC address)."""
    headers = _wigle_headers()
    if not headers:
        return []

    resp = make_request(
        f"{WIGLE_BASE}/network/search?netid={bssid}",
        headers=headers,
        timeout=20,
    )

    if not resp or resp.status_code != 200:
        return []

    data = resp.json()
    return [{
        "ssid": net.get("ssid", ""),
        "bssid": net.get("netid", ""),
        "encryption": net.get("encryption", "Unknown"),
        "latitude": net.get("trilat", 0),
        "longitude": net.get("trilong", 0),
        "city": net.get("city", ""),
        "country": net.get("country", ""),
        "last_seen": net.get("lastupdt", ""),
    } for net in data.get("results", [])]


# ── SSID Pattern Matching ────────────────────────────────────────────

def _generate_ssid_patterns(org_name: str) -> list:
    """Generate likely SSID patterns for an organization."""
    name = org_name.strip()
    parts = name.split()

    patterns = [
        name,                               # Full name
        name.replace(" ", ""),              # NoSpaces
        name.replace(" ", "-"),             # Hyphenated
        name.replace(" ", "_"),             # Underscored
        name.upper(),                       # UPPERCASE
        name.lower(),                       # lowercase
    ]

    # Common corporate SSID suffixes
    suffixes = ["", "-Guest", "-Corp", "-Staff", "-WiFi", "-5G", "-Internal",
                "-Secure", "-Public", "-Employee", "_Guest", "_Corp"]

    expanded = []
    for base in patterns[:3]:  # Top 3 base patterns
        for suffix in suffixes:
            expanded.append(f"{base}{suffix}")

    # Abbreviation (first letters)
    if len(parts) > 1:
        abbrev = "".join(w[0] for w in parts if w).upper()
        expanded.append(abbrev)
        expanded.append(f"{abbrev}-Guest")
        expanded.append(f"{abbrev}-Corp")

    return list(set(expanded))


# ── Free Alternatives (No API Key) ───────────────────────────────────

def _openwifimap_search(lat: float, lon: float) -> list:
    """Search OpenWiFiMap (community, no key needed)."""
    results = []

    # OpenWiFiMap GeoJSON endpoint
    resp = make_request(
        f"https://api.openwifimap.net/view_nodes_spatial?"
        f"bbox={lon - 0.01},{lat - 0.01},{lon + 0.01},{lat + 0.01}",
        timeout=10,
    )
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            for feature in data.get("rows", []):
                doc = feature.get("doc", {})
                results.append({
                    "ssid": doc.get("hostname", "Unknown"),
                    "type": "Community WiFi",
                    "latitude": doc.get("lat", 0),
                    "longitude": doc.get("lon", 0),
                })
        except Exception:
            pass

    return results


def _generate_manual_lookups(query: str) -> list:
    """Generate manual lookup URLs for WiFi intel."""
    return [
        {
            "service": "WiGLE Map",
            "url": f"https://wigle.net/search#ssid={query}",
            "note": "Interactive map of matching SSIDs",
        },
        {
            "service": "WiGLE Stats",
            "url": "https://wigle.net/stats",
            "note": "Global WiFi network statistics",
        },
        {
            "service": "3WiFi (RU)",
            "url": f"https://3wifi.stascorp.com/find?ssid={query}",
            "note": "Russian WiFi database — may have router credentials",
        },
    ]


# ════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ════════════════════════════════════════════════════════════════════════

def wifi_ssid_search(query: str) -> dict:
    """Search for WiFi networks by SSID pattern."""
    print_section("WiFi SSID Intelligence")
    results = {"query": query, "networks": [], "patterns": [], "manual_lookups": []}

    console.print(f"[bold]SSID Search:[/bold] {query}\n")

    has_wigle = bool(_wigle_headers())

    # ── Step 1: Generate SSID patterns ──
    console.print("[bold]Step 1:[/bold] Generating SSID Patterns\n")
    patterns = _generate_ssid_patterns(query)
    results["patterns"] = patterns

    pattern_table = create_table("Likely SSID Patterns", [("#", "dim"), ("Pattern", "white")])
    for i, p in enumerate(patterns[:20], 1):
        pattern_table.add_row(str(i), p)
    console.print(pattern_table)

    # ── Step 2: WiGLE Search ──
    if has_wigle:
        console.print("\n[bold]Step 2:[/bold] WiGLE Network Search\n")

        all_networks = []
        searched = set()

        # Search top patterns
        for pattern in patterns[:5]:
            if pattern.lower() in searched:
                continue
            searched.add(pattern.lower())

            console.print(f"  [dim]Searching: {pattern}...[/dim]")
            networks = _wigle_search_ssid(pattern)
            if networks:
                all_networks.extend(networks)
                print_found(f"'{pattern}'", f"{len(networks)} network(s)")
            else:
                print_not_found(f"'{pattern}'")

        # Deduplicate by BSSID
        seen_bssid = set()
        unique_networks = []
        for net in all_networks:
            bssid = net.get("bssid", "")
            if bssid not in seen_bssid:
                seen_bssid.add(bssid)
                unique_networks.append(net)

        results["networks"] = unique_networks

        if unique_networks:
            console.print(f"\n  [bold cyan]Total unique networks: {len(unique_networks)}[/bold cyan]\n")

            net_table = create_table("Discovered WiFi Networks", [
                ("SSID", "cyan"), ("BSSID", "dim"), ("Encryption", "yellow"),
                ("Location", "white"), ("Last Seen", "dim"),
            ])
            for net in unique_networks[:30]:
                location = f"{net.get('city', '?')}, {net.get('country', '?')}"
                if net.get("latitude") and net.get("longitude"):
                    location += f" ({net['latitude']:.4f}, {net['longitude']:.4f})"
                net_table.add_row(
                    net["ssid"][:30], net["bssid"],
                    net["encryption"], location[:50],
                    net.get("last_seen", "-")[:10],
                )
            console.print(net_table)

            if len(unique_networks) > 30:
                console.print(f"  [dim]... showing 30 of {len(unique_networks)} networks[/dim]")

            # Show Google Maps links for located networks
            geolocated = [n for n in unique_networks if n.get("latitude") and n.get("longitude")]
            if geolocated:
                console.print(f"\n  [bold]Geolocated networks: {len(geolocated)}[/bold]")
                for net in geolocated[:5]:
                    maps_url = f"https://www.google.com/maps?q={net['latitude']},{net['longitude']}"
                    console.print(f"    [green]📍[/green] {net['ssid']} → {maps_url}")
        else:
            print_not_found("No WiFi networks found matching patterns")

    else:
        console.print("\n[bold]Step 2:[/bold] WiGLE Search\n")
        print_warning("WiGLE API key not configured (set HEYES_WIGLE_NAME and HEYES_WIGLE_TOKEN)")
        print_info("Sign up at https://wigle.net/account")

    # ── Step 3: Manual Lookup URLs ──
    console.print("\n[bold]Step 3:[/bold] Manual Lookup Resources\n")
    manual = _generate_manual_lookups(query)
    results["manual_lookups"] = manual

    man_table = create_table("Manual Lookup URLs", [
        ("Service", "cyan"), ("URL", "white"), ("Note", "dim"),
    ])
    for m in manual:
        man_table.add_row(m["service"], m["url"], m["note"])
    console.print(man_table)

    # ── Summary ──
    total = len(results["networks"])
    console.print(f"\n[bold green]WiFi SSID scan complete — {total} network(s) found, "
                  f"{len(patterns)} patterns generated[/bold green]")

    return results


def wifi_location_search(lat: float, lon: float, radius_km: float = 0.5) -> dict:
    """Search for WiFi networks near a GPS location."""
    print_section("WiFi Location Search")
    results = {"latitude": lat, "longitude": lon, "radius_km": radius_km, "networks": []}

    console.print(f"[bold]Location:[/bold] {lat}, {lon}")
    console.print(f"[bold]Radius:[/bold] {radius_km} km\n")

    has_wigle = bool(_wigle_headers())

    if has_wigle:
        console.print("[dim]Searching WiGLE...[/dim]\n")
        networks = _wigle_search_location(lat, lon, radius_km)
        results["networks"] = networks

        if networks:
            table = create_table(f"WiFi Networks within {radius_km}km", [
                ("SSID", "cyan"), ("BSSID", "dim"), ("Encryption", "yellow"),
                ("Lat", "white"), ("Lon", "white"), ("Last Seen", "dim"),
            ])
            for net in networks[:50]:
                table.add_row(
                    net["ssid"][:30], net["bssid"], net["encryption"],
                    f"{net['latitude']:.6f}", f"{net['longitude']:.6f}",
                    net.get("last_seen", "-")[:10],
                )
            console.print(table)
            print_found("Networks Found", str(len(networks)))
        else:
            print_not_found("No networks found in this area")
    else:
        print_warning("WiGLE API key required for location search")
        print_info("Sign up at https://wigle.net/account")

    # Free alternatives
    console.print("\n[bold]Community Data[/bold]\n")
    community = _openwifimap_search(lat, lon)
    if community:
        for net in community[:10]:
            print_found(net["ssid"], f"Community WiFi at {net['latitude']:.4f}, {net['longitude']:.4f}")

    maps_url = f"https://www.google.com/maps?q={lat},{lon}"
    console.print(f"\n  [dim]Google Maps: {maps_url}[/dim]")
    console.print(f"  [dim]WiGLE Map: https://wigle.net/search#lat={lat}&lng={lon}[/dim]")

    return results


def wifi_bssid_lookup(bssid: str) -> dict:
    """Lookup a specific BSSID (MAC address) for geolocation."""
    print_section("WiFi BSSID Lookup")
    results = {"bssid": bssid, "networks": []}

    console.print(f"[bold]BSSID:[/bold] {bssid}\n")

    # Validate MAC format
    mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    if not re.match(mac_pattern, bssid):
        print_error("Invalid BSSID/MAC format. Use XX:XX:XX:XX:XX:XX")
        return results

    has_wigle = bool(_wigle_headers())

    if has_wigle:
        console.print("[dim]Looking up BSSID on WiGLE...[/dim]\n")
        networks = _wigle_search_bssid(bssid)
        results["networks"] = networks

        if networks:
            for net in networks:
                print_found("SSID", net.get("ssid", "Hidden"))
                print_found("Encryption", net.get("encryption", "Unknown"))
                if net.get("latitude") and net.get("longitude"):
                    print_found("Location", f"{net['latitude']:.6f}, {net['longitude']:.6f}")
                    print_found("Google Maps",
                               f"https://www.google.com/maps?q={net['latitude']},{net['longitude']}")
                print_found("City", f"{net.get('city', '?')}, {net.get('country', '?')}")
                print_found("Last Seen", net.get("last_seen", "Unknown"))
        else:
            print_not_found("BSSID not found in WiGLE database")
    else:
        print_warning("WiGLE API key required")

    # Apple/Google geolocation API note
    print_info("Tip: Apple & Google also geolocate BSSIDs via their location services APIs")
    console.print(f"  [dim]Manual lookup: https://wigle.net/search#netid={bssid}[/dim]")

    return results
