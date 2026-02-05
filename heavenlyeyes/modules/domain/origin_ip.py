"""Origin IP discovery — find real IPs behind CDN/WAF (Cloudflare, Akamai, etc.)."""

import hashlib
import re
import socket
import struct

import dns.resolver
import requests

from heavenlyeyes.core.utils import (
    print_section, print_found, print_not_found, print_info, print_warning,
    print_error, create_table, console, make_request, resolve_host,
)
from heavenlyeyes.core.config import get_api_key, get_timeout

# Known CDN/WAF IP ranges (partial, for detection)
CDN_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server": ["cloudflare"],
        "ip_ranges_v4": [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        ],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-akamai-request-id"],
        "server": ["akamai", "akamaighost"],
    },
    "AWS CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "server": ["cloudfront", "amazons3"],
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-io-info"],
        "server": ["fastly"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
    },
    "Incapsula/Imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["incapsula"],
    },
    "StackPath/MaxCDN": {
        "headers": ["x-hw"],
        "server": ["stackpath", "netdna", "maxcdn"],
    },
    "Azure CDN": {
        "headers": ["x-azure-ref"],
        "server": [],
    },
    "Google Cloud CDN": {
        "headers": ["via"],
        "server": ["google frontend", "gws"],
    },
    "DDoS-Guard": {
        "headers": ["x-ddos-protection"],
        "server": ["ddos-guard"],
    },
}

# Subdomains that typically bypass CDN
BYPASS_SUBDOMAINS = [
    "mail", "email", "webmail", "smtp", "pop", "pop3", "imap",
    "mx", "mx1", "mx2", "mx3",
    "ftp", "sftp",
    "direct", "direct-connect",
    "origin", "origin-www",
    "cpanel", "whm", "webdisk", "cpcalendars", "cpcontacts",
    "autodiscover", "autoconfig",
    "ns1", "ns2", "ns3", "ns4",
    "vpn", "remote", "gateway",
    "dev", "staging", "stage", "test",
    "old", "legacy", "backup",
    "api", "api-internal",
    "internal", "intranet",
    "admin", "panel", "dashboard",
    "db", "database", "mysql", "postgres",
    "ssh", "rdp",
    "monitor", "grafana", "jenkins", "ci",
    "owa", "exchange",
    "crm", "erp",
]


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """Check if an IP is within a CIDR range."""
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        network, bits = cidr.split("/")
        net_int = struct.unpack("!I", socket.inet_aton(network))[0]
        mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
        return (ip_int & mask) == (net_int & mask)
    except Exception:
        return False


def _is_cdn_ip(ip: str) -> str | None:
    """Check if an IP belongs to a known CDN."""
    for cdn_name, info in CDN_SIGNATURES.items():
        for cidr in info.get("ip_ranges_v4", []):
            if _ip_in_cidr(ip, cidr):
                return cdn_name
    return None


# ── CDN/WAF Detection ──────────────────────────────────────────────────

def detect_cdn_waf(domain: str) -> dict:
    """Detect which CDN/WAF is protecting the domain."""
    print_section("CDN / WAF Detection")

    result = {"detected": [], "current_ip": None, "is_proxied": False}

    # Resolve current IP
    ip = resolve_host(domain)
    if ip:
        result["current_ip"] = ip
        print_found("Current IP", ip)

        cdn = _is_cdn_ip(ip)
        if cdn:
            result["is_proxied"] = True
            result["detected"].append(cdn)
            print_warning(f"IP belongs to {cdn} range — domain is proxied")
    else:
        print_error("Could not resolve domain")
        return result

    # Check HTTP headers
    for proto in ("https", "http"):
        resp = make_request(f"{proto}://{domain}")
        if not resp:
            continue

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        server = headers_lower.get("server", "").lower()

        for cdn_name, sigs in CDN_SIGNATURES.items():
            # Check headers
            for hdr in sigs.get("headers", []):
                if hdr.lower() in headers_lower:
                    if cdn_name not in result["detected"]:
                        result["detected"].append(cdn_name)
                        result["is_proxied"] = True
                        print_warning(f"Detected {cdn_name} (header: {hdr})")

            # Check server header
            for srv in sigs.get("server", []):
                if srv in server:
                    if cdn_name not in result["detected"]:
                        result["detected"].append(cdn_name)
                        result["is_proxied"] = True
                        print_warning(f"Detected {cdn_name} (server: {server})")
        break

    if not result["detected"]:
        print_found("Status", "No CDN/WAF detected — IP may be the origin")
        result["is_proxied"] = False

    return result


# ── Origin IP Discovery ────────────────────────────────────────────────

def find_origin_ip(domain: str) -> dict:
    """Attempt to discover the real origin IP behind CDN/WAF."""
    print_section("Origin IP Discovery")

    results = {
        "cdn_detected": [],
        "candidates": {},
        "methods_used": [],
    }

    # Step 1: Detect CDN
    cdn_info = detect_cdn_waf(domain)
    results["cdn_detected"] = cdn_info["detected"]

    if not cdn_info["is_proxied"]:
        print_info("Domain does not appear to be behind a CDN — current IP is likely the origin")
        results["candidates"][cdn_info["current_ip"]] = {
            "source": "Direct DNS resolution",
            "confidence": "HIGH",
        }
        return results

    console.print()
    print_info("CDN detected — attempting origin IP discovery...\n")

    # Step 2: Check MX records for origin IP
    _check_mx_records(domain, results)

    # Step 3: Check SPF records for origin IP
    _check_spf_records(domain, results)

    # Step 4: Check unproxied subdomains
    _check_bypass_subdomains(domain, cdn_info, results)

    # Step 5: Check historical DNS via ViewDNS
    _check_dns_history(domain, results)

    # Step 6: Shodan deep search (SSL cert, hostname, title, favicon)
    _check_shodan(domain, results)

    # Step 7: Check SSL certificate matches via Censys
    _check_censys(domain, results)

    # Step 8: Check HTTP header leaks
    _check_header_leaks(domain, results)

    # Step 9: Favicon hash search (fallback if no Shodan key)
    _check_favicon_hash(domain, results)

    # Step 10: Verify candidates via Shodan host lookup
    _verify_candidates_shodan(domain, results)

    # ── Summary ──
    _display_results(domain, cdn_info, results)

    return results


def _check_mx_records(domain: str, results: dict):
    """Check MX records — mail servers often reveal origin IP.

    Enhancement: Also checks if the MX IP responds to HTTP (same-server indicator)
    and performs subnet correlation with other candidates.
    """
    results["methods_used"].append("MX / SMTP Leak Analysis")
    mx_ips = []
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip(".")
            ip = resolve_host(mx_host)
            if not ip:
                continue

            mx_ips.append(ip)
            is_cdn = _is_cdn_ip(ip)

            if domain in mx_host and not is_cdn:
                results["candidates"][ip] = {
                    "source": f"MX record ({mx_host})",
                    "confidence": "HIGH",
                }
                print_found("MX Origin", f"{ip} via {mx_host}")
            elif not is_cdn:
                print_info(f"MX server: {mx_host} ({ip})")

            # ── HTTP probe on MX IP — if it serves web content, likely the origin ──
            if not is_cdn:
                http_match = _http_probe_ip(ip, domain)
                if http_match:
                    results["candidates"][ip] = {
                        "source": f"MX IP responds to HTTP ({mx_host})",
                        "confidence": "HIGH",
                    }
                    print_found(
                        "[bold green]MX+HTTP MATCH[/bold green]",
                        f"{ip} — mail server also serves HTTP for {domain}",
                    )

        # ── Subnet correlation — check if MX IP is near other candidates ──
        if mx_ips:
            _subnet_correlation(mx_ips, domain, results)

    except Exception:
        pass


def _http_probe_ip(ip: str, domain: str) -> bool:
    """Probe an IP to see if it serves HTTP content for the domain."""
    for proto in ("https", "http"):
        try:
            resp = requests.get(
                f"{proto}://{ip}",
                headers={"Host": domain, "User-Agent": "HeavenlyEyes/2.0"},
                timeout=5,
                verify=False,
                allow_redirects=False,
            )
            if resp.status_code in (200, 301, 302, 403):
                # Check if it actually knows about the domain
                body = resp.text[:2000].lower()
                if domain.lower() in body or resp.status_code in (200, 301, 302):
                    return True
        except Exception:
            pass
    return False


def _subnet_correlation(mx_ips: list[str], domain: str, results: dict):
    """Check if MX IPs share a /24 subnet with any candidate — strong origin signal."""
    existing = list(results.get("candidates", {}).keys())
    for mx_ip in mx_ips:
        mx_prefix = ".".join(mx_ip.split(".")[:3])
        for candidate_ip in existing:
            cand_prefix = ".".join(candidate_ip.split(".")[:3])
            if mx_prefix == cand_prefix and mx_ip != candidate_ip:
                print_found(
                    "[bold green]SUBNET MATCH[/bold green]",
                    f"MX {mx_ip} shares /24 with candidate {candidate_ip} — strong origin signal",
                )
                # Upgrade candidate confidence
                if candidate_ip in results["candidates"]:
                    results["candidates"][candidate_ip]["confidence"] = "HIGH"
                    results["candidates"][candidate_ip]["subnet_match"] = mx_ip


def _check_spf_records(domain: str, results: dict):
    """Check SPF/TXT records for IP addresses."""
    results["methods_used"].append("SPF/TXT Records")
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for txt in txt_records:
            record = str(txt).strip('"')
            if "v=spf1" in record:
                # Extract ip4: directives
                ip4_matches = re.findall(r"ip4:(\d+\.\d+\.\d+\.\d+(?:/\d+)?)", record)
                for ip_or_cidr in ip4_matches:
                    ip = ip_or_cidr.split("/")[0]
                    if not _is_cdn_ip(ip):
                        results["candidates"][ip] = {
                            "source": f"SPF record (ip4:{ip_or_cidr})",
                            "confidence": "HIGH",
                        }
                        print_found("SPF Origin", f"{ip} from SPF ip4 directive")

                # Extract 'a' and 'include' directives for further resolution
                a_matches = re.findall(r"\ba[:/](\S+)", record)
                for host in a_matches:
                    host = host.rstrip(".")
                    ip = resolve_host(host)
                    if ip and not _is_cdn_ip(ip):
                        results["candidates"][ip] = {
                            "source": f"SPF 'a' record ({host})",
                            "confidence": "MEDIUM",
                        }
                        print_found("SPF Origin", f"{ip} via SPF a:{host}")
    except Exception:
        pass


def _check_bypass_subdomains(domain: str, cdn_info: dict, results: dict):
    """Check subdomains that typically bypass CDN.

    Enhancement: Multi-threaded + HTTP-probes discovered IPs to verify they serve
    the same content as the main domain.
    """
    import concurrent.futures

    results["methods_used"].append("Subdomain Bypass + HTTP Verification")
    print_info(f"Checking {len(BYPASS_SUBDOMAINS)} subdomains for CDN bypass (threaded)...")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    found_count = 0

    def check_sub(sub):
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            for rdata in answers:
                ip = str(rdata)
                if ip != cdn_info.get("current_ip") and not _is_cdn_ip(ip):
                    return (sub, fqdn, ip)
        except Exception:
            pass
        return None

    # Threaded subdomain resolution
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(check_sub, sub): sub for sub in BYPASS_SUBDOMAINS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                sub, fqdn, ip = result
                high_value = sub in (
                    "mail", "ftp", "direct", "origin", "cpanel", "webmail",
                    "smtp", "imap", "pop", "pop3", "owa", "exchange",
                )
                confidence = "HIGH" if high_value else "MEDIUM"

                if ip not in results["candidates"]:
                    results["candidates"][ip] = {
                        "source": f"Subdomain bypass ({fqdn})",
                        "confidence": confidence,
                    }
                    print_found("Bypass IP", f"{ip} via {fqdn}")
                    found_count += 1

                    # HTTP-probe: does this IP serve the main domain?
                    if _http_probe_ip(ip, domain):
                        results["candidates"][ip]["confidence"] = "HIGH"
                        results["candidates"][ip]["http_verified"] = True
                        print_found(
                            "[bold green]HTTP VERIFIED[/bold green]",
                            f"{ip} ({fqdn}) serves HTTP content for {domain}",
                        )

    if found_count == 0:
        print_info("No unproxied subdomains found")
    else:
        print_info(f"Found {found_count} unproxied subdomain(s)")


def _check_dns_history(domain: str, results: dict):
    """Check historical DNS records for pre-CDN IPs.

    Uses SecurityTrails API (if key available) + ViewDNS.info scraping.
    Shows a formatted table of the last known IPs with dates.
    """
    results["methods_used"].append("Historical DNS Snapshots")

    history_entries = []  # list of {ip, date, source}

    # ── SecurityTrails API (best source) ──
    st_key = get_api_key("securitytrails")
    if st_key:
        print_info("Querying SecurityTrails for DNS history...")
        resp = make_request(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"apikey": st_key, "Accept": "application/json"},
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                for record in data.get("records", []):
                    for val in record.get("values", []):
                        ip = val.get("ip", "")
                        if ip:
                            history_entries.append({
                                "ip": ip,
                                "date": record.get("last_seen", "?"),
                                "first_seen": record.get("first_seen", "?"),
                                "source": "SecurityTrails",
                                "org": record.get("organizations", [""])[0] if record.get("organizations") else "",
                            })
            except Exception:
                pass
    else:
        print_info("No SecurityTrails key — add HEYES_SECURITYTRAILS for premium DNS history")

    # ── ViewDNS.info scraping (free fallback) ──
    resp = make_request(f"https://viewdns.info/iphistory/?domain={domain}")
    if resp and resp.status_code == 200:
        # Parse table rows: IP | Location | Owner | Last seen
        rows = re.findall(
            r"<tr><td>(\d+\.\d+\.\d+\.\d+)</td><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td></tr>",
            resp.text,
        )
        if rows:
            for ip, location, owner, date in rows:
                if not any(e["ip"] == ip and e["source"] == "ViewDNS" for e in history_entries):
                    history_entries.append({
                        "ip": ip,
                        "date": date.strip(),
                        "source": "ViewDNS",
                        "org": owner.strip(),
                    })
        else:
            # Simpler fallback — just IPs
            ip_matches = re.findall(r"<td>(\d+\.\d+\.\d+\.\d+)</td>", resp.text)
            for ip in ip_matches:
                if not any(e["ip"] == ip for e in history_entries):
                    history_entries.append({"ip": ip, "date": "?", "source": "ViewDNS", "org": ""})

    # ── Display and process ──
    if history_entries:
        table = create_table(
            f"Historical DNS for {domain}",
            [("IP Address", "white"), ("Last Seen", "dim"), ("Org/Owner", "dim"), ("Source", "dim"), ("CDN?", "yellow")],
        )
        seen_ips = set()
        for entry in history_entries:
            ip = entry["ip"]
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            cdn = _is_cdn_ip(ip)
            cdn_label = f"[yellow]{cdn}[/yellow]" if cdn else "[green]No[/green]"
            table.add_row(ip, entry.get("date", "?"), entry.get("org", ""), entry["source"], cdn_label)

            if not cdn and ip not in results["candidates"]:
                results["candidates"][ip] = {
                    "source": f"DNS history ({entry['source']}, last: {entry.get('date', '?')})",
                    "confidence": "MEDIUM",
                }

        console.print(table)

        non_cdn = [e["ip"] for e in history_entries if not _is_cdn_ip(e["ip"])]
        if non_cdn:
            unique = list(dict.fromkeys(non_cdn))
            print_found("Pre-CDN IPs", ", ".join(unique[:5]))
            print_info(f"{len(unique)} historical non-CDN IP(s) found — these are likely the origin")
    else:
        print_info("No historical DNS records found")


def _check_shodan(domain: str, results: dict):
    """Full Shodan search — SSL cert, hostname, HTTP title, favicon hash, Host header."""
    shodan_key = get_api_key("shodan")
    if not shodan_key:
        print_info("No Shodan API key — skipping Shodan deep search")
        print_info("Set HEYES_SHODAN env var or add to ~/.heavenlyeyes/config.yaml")
        return

    results["methods_used"].append("Shodan Deep Search")
    print_info("Running Shodan deep search (SSL + hostname + title + favicon)...")

    queries = {}

    # 1. SSL certificate CN match — most reliable
    queries["ssl_cn"] = {
        "query": f"ssl.cert.subject.cn:{domain}",
        "label": "Shodan SSL cert CN",
        "confidence": "HIGH",
    }

    # 2. SSL certificate SAN match
    queries["ssl_san"] = {
        "query": f'ssl.cert.extensions.subjectAltName:"{domain}"',
        "label": "Shodan SSL cert SAN",
        "confidence": "HIGH",
    }

    # 3. Hostname match — servers that DNS resolves to this domain
    queries["hostname"] = {
        "query": f"hostname:{domain}",
        "label": "Shodan hostname",
        "confidence": "MEDIUM",
    }

    # 4. HTTP Host header — servers configured to respond to this domain
    queries["http_host"] = {
        "query": f'http.host:"{domain}"',
        "label": "Shodan HTTP Host header",
        "confidence": "HIGH",
    }

    # 5. Get page title for title-based search
    page_title = _get_page_title(domain)
    if page_title and len(page_title) > 5:
        queries["http_title"] = {
            "query": f'http.title:"{page_title}"',
            "label": f"Shodan HTTP title match (\"{page_title[:40]}\")",
            "confidence": "MEDIUM",
        }

    # 6. Favicon hash
    fav_hash = _compute_favicon_hash(domain)
    if fav_hash:
        queries["favicon"] = {
            "query": f"http.favicon.hash:{fav_hash}",
            "label": "Shodan favicon hash",
            "confidence": "HIGH",
        }
        results["favicon_hash"] = fav_hash
        print_found("Favicon Hash (mmh3)", str(fav_hash))

    # Run all queries and collect ALL matches for the table
    all_shodan_hits = {}  # ip -> {meta + which queries matched}
    total_found = 0

    for key, info in queries.items():
        ips = _shodan_search(shodan_key, info["query"])
        for ip, meta in ips.items():
            is_cdn = _is_cdn_ip(ip)
            if ip not in all_shodan_hits:
                all_shodan_hits[ip] = {
                    "ports": meta.get("ports", []),
                    "org": meta.get("org", ""),
                    "isp": meta.get("isp", ""),
                    "is_cdn": is_cdn,
                    "matched_queries": [],
                }
            all_shodan_hits[ip]["matched_queries"].append(info["label"])

            if not is_cdn and ip not in results["candidates"]:
                # More queries matched = higher confidence
                confidence = info["confidence"]
                results["candidates"][ip] = {
                    "source": info["label"],
                    "confidence": confidence,
                    "shodan_ports": meta.get("ports", []),
                    "shodan_org": meta.get("org", ""),
                }
                total_found += 1

    # ── Display Shodan results as a rich table ──
    if all_shodan_hits:
        table = create_table(
            f"Shodan Discovery — {len(all_shodan_hits)} server(s) found globally",
            [
                ("IP Address", "white"),
                ("Org / ISP", "dim"),
                ("Ports", "cyan"),
                ("Matched Queries", "green"),
                ("CDN?", "yellow"),
                ("Verdict", "bold"),
            ],
        )
        for ip, meta in sorted(all_shodan_hits.items(), key=lambda x: len(x[1]["matched_queries"]), reverse=True):
            ports = ", ".join(str(p) for p in meta["ports"][:6])
            queries_matched = ", ".join(meta["matched_queries"][:3])
            cdn_label = f"[yellow]{meta['is_cdn']}[/yellow]" if meta["is_cdn"] else "[green]No[/green]"

            match_count = len(meta["matched_queries"])
            if meta["is_cdn"]:
                verdict = "[dim]CDN node[/dim]"
            elif match_count >= 3:
                verdict = "[bold green]★ LIKELY ORIGIN[/bold green]"
            elif match_count >= 2:
                verdict = "[green]Strong match[/green]"
            else:
                verdict = "[yellow]Possible[/yellow]"

            table.add_row(ip, meta.get("org", ""), ports, queries_matched, cdn_label, verdict)

            # Upgrade candidates that matched multiple queries
            if not meta["is_cdn"] and match_count >= 2 and ip in results["candidates"]:
                results["candidates"][ip]["confidence"] = "HIGH"
                results["candidates"][ip]["shodan_multi_match"] = match_count

        console.print(table)

        non_cdn = [ip for ip, m in all_shodan_hits.items() if not m["is_cdn"]]
        if non_cdn:
            best = max(non_cdn, key=lambda ip: len(all_shodan_hits[ip]["matched_queries"]))
            match_count = len(all_shodan_hits[best]["matched_queries"])
            console.print(
                f"\n  [bold green]★ Best Shodan match:[/bold green] {best} "
                f"(matched {match_count} queries, org: {all_shodan_hits[best].get('org', '?')})"
            )
        print_info(f"Shodan found {total_found} non-CDN candidate(s) across {len(all_shodan_hits)} total server(s)")
    else:
        print_info("Shodan returned no results")


def _shodan_search(api_key: str, query: str, max_results: int = 50) -> dict:
    """Execute a Shodan search query and return {ip: metadata} dict."""
    results = {}
    try:
        resp = make_request(
            "https://api.shodan.io/shodan/host/search",
            params={"key": api_key, "query": query, "minify": "true"},
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            for match in data.get("matches", [])[:max_results]:
                ip = match.get("ip_str", "")
                if ip:
                    if ip not in results:
                        results[ip] = {
                            "ports": [],
                            "org": match.get("org", ""),
                            "isp": match.get("isp", ""),
                            "os": match.get("os", ""),
                        }
                    port = match.get("port")
                    if port and port not in results[ip]["ports"]:
                        results[ip]["ports"].append(port)
        elif resp and resp.status_code == 401:
            print_error("Shodan API key is invalid")
        elif resp and resp.status_code == 429:
            print_warning("Shodan rate limit hit — try again later")
    except Exception:
        pass
    return results


def _get_page_title(domain: str) -> str | None:
    """Get the HTML page title of a domain."""
    for proto in ("https", "http"):
        resp = make_request(f"{proto}://{domain}")
        if resp and resp.status_code == 200:
            match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                # Clean up and truncate for Shodan query
                title = re.sub(r"\s+", " ", title)
                return title[:80] if len(title) > 80 else title
    return None


def _compute_favicon_hash(domain: str) -> int | None:
    """Compute Shodan-compatible mmh3 favicon hash."""
    for proto in ("https", "http"):
        resp = make_request(f"{proto}://{domain}/favicon.ico")
        if resp and resp.status_code == 200 and len(resp.content) > 0:
            try:
                import mmh3
                import base64
                encoded = base64.encodebytes(resp.content)
                return mmh3.hash(encoded)
            except ImportError:
                # mmh3 not installed — try codecs approach
                try:
                    import base64
                    import struct as _struct
                    encoded = base64.encodebytes(resp.content)
                    return _mmh3_hash(encoded)
                except Exception:
                    return None
    return None


def _mmh3_hash(data: bytes, seed: int = 0) -> int:
    """Pure Python implementation of MurmurHash3 (32-bit) for Shodan favicon matching."""
    if isinstance(data, str):
        data = data.encode("utf-8")

    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF

    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for i in range(nblocks):
        idx = i * 4
        k1 = (
            data[idx]
            | (data[idx + 1] << 8)
            | (data[idx + 2] << 16)
            | (data[idx + 3] << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail_idx = nblocks * 4
    k1 = 0
    tail_size = length & 3

    if tail_size >= 3:
        k1 ^= data[tail_idx + 2] << 16
    if tail_size >= 2:
        k1 ^= data[tail_idx + 1] << 8
    if tail_size >= 1:
        k1 ^= data[tail_idx]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    # Convert to signed 32-bit int (Shodan uses signed)
    if h1 >= 0x80000000:
        h1 -= 0x100000000

    return h1


def _check_censys(domain: str, results: dict):
    """Search Censys for SSL certificates matching the domain."""
    results["methods_used"].append("SSL Certificate Search (Censys)")

    api_id = get_api_key("censys_id")
    api_secret = get_api_key("censys_secret")

    if not api_id or not api_secret:
        # Try free search via crt.sh
        _check_crtsh(domain, results)
        return

    resp = make_request(
        "https://search.censys.io/api/v2/hosts/search",
        method="GET",
        params={"q": f"services.tls.certificates.leaf.names: {domain}", "per_page": 25},
        auth=(api_id, api_secret),
    )
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            for hit in data.get("result", {}).get("hits", []):
                ip = hit.get("ip")
                if ip and not _is_cdn_ip(ip):
                    if ip not in results["candidates"]:
                        results["candidates"][ip] = {
                            "source": "Censys SSL certificate search",
                            "confidence": "HIGH",
                        }
                        print_found("Censys Origin", ip)
        except Exception:
            pass
    else:
        _check_crtsh(domain, results)


def _check_crtsh(domain: str, results: dict):
    """Use crt.sh to find certificate transparency logs, then resolve unique hosts."""
    resp = make_request(f"https://crt.sh/?q=%.{domain}&output=json")
    if resp and resp.status_code == 200:
        try:
            certs = resp.json()
            unique_names = set()
            for cert in certs[:50]:
                name = cert.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain) and n != domain:
                        unique_names.add(n)

            for name in list(unique_names)[:20]:
                ip = resolve_host(name)
                if ip and not _is_cdn_ip(ip):
                    if ip not in results["candidates"]:
                        results["candidates"][ip] = {
                            "source": f"CT log subdomain ({name})",
                            "confidence": "MEDIUM",
                        }
                        print_found("CT Log IP", f"{ip} via {name}")
        except Exception:
            pass
    else:
        print_info("crt.sh lookup unavailable")


def _check_header_leaks(domain: str, results: dict):
    """Check for origin IP leaks in HTTP response headers."""
    results["methods_used"].append("HTTP Header Analysis")

    leak_headers = [
        "x-real-ip", "x-originating-ip", "x-remote-ip", "x-forwarded-for",
        "x-host", "x-remote-addr", "x-backend-server", "x-origin-server",
        "x-served-by", "x-backend", "x-upstream",
    ]

    for proto in ("https", "http"):
        resp = make_request(f"{proto}://{domain}")
        if not resp:
            continue

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for hdr in leak_headers:
            val = headers_lower.get(hdr, "")
            if val:
                ips = re.findall(r"\d+\.\d+\.\d+\.\d+", val)
                for ip in ips:
                    if not _is_cdn_ip(ip):
                        results["candidates"][ip] = {
                            "source": f"Header leak ({hdr}: {val})",
                            "confidence": "HIGH",
                        }
                        print_found("Header Leak", f"{ip} from {hdr}")
        break

    print_info("Header analysis complete")


def _check_favicon_hash(domain: str, results: dict):
    """Fallback favicon hash when Shodan key is unavailable."""
    # Skip if Shodan already handled this
    if "Shodan Deep Search" in results.get("methods_used", []):
        return

    results["methods_used"].append("Favicon Hash (manual)")

    fav_hash = _compute_favicon_hash(domain)
    if fav_hash:
        results["favicon_hash"] = fav_hash
        print_found("Favicon Hash", str(fav_hash))
        print_info(f"Manual Shodan search: https://www.shodan.io/search?query=http.favicon.hash%3A{fav_hash}")
        print_info("Add a Shodan API key to auto-search this hash")
    else:
        # MD5 fallback
        for proto in ("https", "http"):
            resp = make_request(f"{proto}://{domain}/favicon.ico")
            if resp and resp.status_code == 200 and len(resp.content) > 0:
                fav_md5 = hashlib.md5(resp.content).hexdigest()
                results["favicon_md5"] = fav_md5
                print_found("Favicon MD5", fav_md5)
                break


def _verify_candidates_shodan(domain: str, results: dict):
    """Verify candidate IPs by checking if they serve the domain via Shodan host lookup."""
    shodan_key = get_api_key("shodan")
    if not shodan_key:
        return

    candidates = list(results.get("candidates", {}).keys())
    if not candidates:
        return

    print_info(f"Verifying {len(candidates)} candidate(s) via Shodan host lookup...")

    for ip in candidates[:10]:  # Limit to avoid rate limits
        try:
            resp = make_request(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": shodan_key, "minify": "true"},
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                hostnames = data.get("hostnames", [])
                org = data.get("org", "")
                ports = data.get("ports", [])

                # Check if this IP is associated with the domain
                domain_match = any(domain in h for h in hostnames)
                if domain_match:
                    # Upgrade confidence if domain appears in hostnames
                    if ip in results["candidates"]:
                        results["candidates"][ip]["confidence"] = "HIGH"
                        results["candidates"][ip]["verified"] = True
                        results["candidates"][ip]["shodan_hostnames"] = hostnames
                        results["candidates"][ip]["shodan_org"] = org
                        results["candidates"][ip]["shodan_ports"] = ports
                        print_found(
                            "Verified",
                            f"{ip} — Shodan confirms domain association "
                            f"[{org}] ports: {', '.join(str(p) for p in ports[:8])}",
                        )
                else:
                    # Still useful info
                    if ip in results["candidates"]:
                        results["candidates"][ip]["shodan_org"] = org
                        results["candidates"][ip]["shodan_ports"] = ports
        except Exception:
            pass


def _display_results(domain: str, cdn_info: dict, results: dict):
    """Display final origin IP discovery results."""
    console.print()
    print_section("Origin IP Results")

    print_info(f"CDN/WAF detected: {', '.join(results['cdn_detected']) or 'None'}")
    print_info(f"Current (proxied) IP: {cdn_info.get('current_ip', 'Unknown')}")
    print_info(f"Methods used: {', '.join(results['methods_used'])}")
    console.print()

    if results["candidates"]:
        table = create_table(
            f"Origin IP Candidates for {domain}",
            [
                ("IP Address", "green"),
                ("Source", "white"),
                ("Org / ISP", "dim"),
                ("Ports", "cyan"),
                ("Confidence", "yellow"),
            ],
        )

        # Sort by confidence, then verified first
        confidence_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_candidates = sorted(
            results["candidates"].items(),
            key=lambda x: (
                0 if x[1].get("verified") else 1,
                confidence_order.get(x[1]["confidence"], 3),
            ),
        )

        for ip, meta in sorted_candidates:
            conf = meta["confidence"]
            color = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(conf, "white")
            verified = " [bold green]✓[/bold green]" if meta.get("verified") else ""
            org = meta.get("shodan_org", "")
            ports = ", ".join(str(p) for p in meta.get("shodan_ports", [])[:6])
            table.add_row(
                f"{ip}{verified}",
                meta["source"],
                org,
                ports,
                f"[{color}]{conf}[/{color}]",
            )

        console.print(table)

        # Show verified IPs prominently
        verified = [ip for ip, m in results["candidates"].items() if m.get("verified")]
        high_conf = [ip for ip, m in results["candidates"].items() if m["confidence"] == "HIGH"]

        if verified:
            console.print(f"\n[bold green]✓ Shodan-verified origin IP(s):[/bold green] {', '.join(verified)}")
        elif high_conf:
            console.print(f"\n[bold green]Most likely origin IP(s):[/bold green] {', '.join(high_conf)}")
        else:
            print_warning("No high-confidence candidates — results need manual verification")
    else:
        print_warning("No origin IP candidates found — CDN may be well-configured")
        print_info("Add a Shodan API key (HEYES_SHODAN) for much deeper results")
