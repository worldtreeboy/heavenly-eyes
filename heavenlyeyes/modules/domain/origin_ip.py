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

    # Step 6: Check SSL certificate matches via Censys
    _check_censys(domain, results)

    # Step 7: Check HTTP header leaks
    _check_header_leaks(domain, results)

    # Step 8: Favicon hash search
    _check_favicon_hash(domain, results)

    # ── Summary ──
    _display_results(domain, cdn_info, results)

    return results


def _check_mx_records(domain: str, results: dict):
    """Check MX records — mail servers often reveal origin IP."""
    results["methods_used"].append("MX Records")
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip(".")
            # If MX points to the same domain, resolve it
            if domain in mx_host:
                ip = resolve_host(mx_host)
                if ip and not _is_cdn_ip(ip):
                    results["candidates"][ip] = {
                        "source": f"MX record ({mx_host})",
                        "confidence": "HIGH",
                    }
                    print_found("MX Origin", f"{ip} via {mx_host}")
            else:
                # External mail — still worth noting
                ip = resolve_host(mx_host)
                if ip:
                    print_info(f"MX points to external: {mx_host} ({ip})")
    except Exception:
        pass


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
    """Check subdomains that typically bypass CDN."""
    results["methods_used"].append("Subdomain Bypass")
    print_info(f"Checking {len(BYPASS_SUBDOMAINS)} subdomains for CDN bypass...")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    found_count = 0

    for sub in BYPASS_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            for rdata in answers:
                ip = str(rdata)
                if ip != cdn_info.get("current_ip") and not _is_cdn_ip(ip):
                    confidence = "HIGH" if sub in ("mail", "ftp", "direct", "origin", "cpanel") else "MEDIUM"
                    if ip not in results["candidates"]:
                        results["candidates"][ip] = {
                            "source": f"Subdomain bypass ({fqdn})",
                            "confidence": confidence,
                        }
                        print_found("Bypass IP", f"{ip} via {fqdn}")
                        found_count += 1
        except Exception:
            pass

    if found_count == 0:
        print_info("No unproxied subdomains found")


def _check_dns_history(domain: str, results: dict):
    """Check historical DNS records for pre-CDN IPs."""
    results["methods_used"].append("DNS History")

    # ViewDNS.info IP History
    resp = make_request(f"https://viewdns.info/iphistory/?domain={domain}")
    if resp and resp.status_code == 200:
        # Parse the HTML table for IPs
        ip_matches = re.findall(
            r"<td>(\d+\.\d+\.\d+\.\d+)</td>",
            resp.text,
        )
        seen = set()
        for ip in ip_matches:
            if ip not in seen and not _is_cdn_ip(ip):
                seen.add(ip)
                if ip not in results["candidates"]:
                    results["candidates"][ip] = {
                        "source": "DNS history (ViewDNS)",
                        "confidence": "MEDIUM",
                    }
                    print_found("Historical IP", f"{ip} (pre-CDN)")

        if not seen:
            print_info("No historical IPs found via ViewDNS")
    else:
        print_info("DNS history lookup unavailable")


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
    """Calculate favicon hash for Shodan search."""
    results["methods_used"].append("Favicon Hash")

    for proto in ("https", "http"):
        resp = make_request(f"{proto}://{domain}/favicon.ico")
        if resp and resp.status_code == 200 and len(resp.content) > 0:
            import base64
            try:
                import mmh3
                favicon_b64 = base64.encodebytes(resp.content)
                fav_hash = mmh3.hash(favicon_b64)
                results["favicon_hash"] = fav_hash
                print_found("Favicon Hash", str(fav_hash))
                print_info(f"Search Shodan: http.favicon.hash:{fav_hash}")

                # If Shodan API key available, search automatically
                shodan_key = get_api_key("shodan")
                if shodan_key:
                    _search_shodan_favicon(fav_hash, shodan_key, domain, results)
                else:
                    print_info("Add a Shodan API key to auto-search for origin by favicon hash")
            except ImportError:
                # Fallback: use standard hashlib
                fav_hash = hashlib.md5(resp.content).hexdigest()
                results["favicon_md5"] = fav_hash
                print_found("Favicon MD5", fav_hash)
                print_info("Install 'mmh3' for Shodan-compatible favicon hash")
            break


def _search_shodan_favicon(fav_hash: int, api_key: str, domain: str, results: dict):
    """Search Shodan for servers with matching favicon hash."""
    resp = make_request(
        f"https://api.shodan.io/shodan/host/search?key={api_key}&query=http.favicon.hash:{fav_hash}",
    )
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            for match in data.get("matches", []):
                ip = match.get("ip_str")
                if ip and not _is_cdn_ip(ip):
                    results["candidates"][ip] = {
                        "source": f"Shodan favicon hash match",
                        "confidence": "HIGH",
                    }
                    print_found("Shodan Match", f"{ip} (favicon hash)")
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
            [("IP Address", "green"), ("Source", "white"), ("Confidence", "yellow")],
        )

        # Sort by confidence
        confidence_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_candidates = sorted(
            results["candidates"].items(),
            key=lambda x: confidence_order.get(x[1]["confidence"], 3),
        )

        for ip, meta in sorted_candidates:
            conf = meta["confidence"]
            color = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(conf, "white")
            table.add_row(ip, meta["source"], f"[{color}]{conf}[/{color}]")

        console.print(table)

        high_conf = [ip for ip, m in results["candidates"].items() if m["confidence"] == "HIGH"]
        if high_conf:
            console.print(f"\n[bold green]Most likely origin IP(s):[/bold green] {', '.join(high_conf)}")
        else:
            print_warning("No high-confidence candidates — results need manual verification")
    else:
        print_warning("No origin IP candidates found — CDN may be well-configured")
        print_info("Try adding Shodan/Censys API keys for deeper analysis")
