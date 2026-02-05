"""Public domain records — WHOIS and DNS lookups."""

import ssl
import socket
import json
from datetime import datetime

import dns.resolver
import whois
from rich.console import Console
from rich.panel import Panel

from heavenlyeyes.core.utils import (
    print_section, print_found, print_not_found, print_error,
    create_table, console,
)

# ── WHOIS ──────────────────────────────────────────────────────────────

def whois_lookup(domain: str) -> dict:
    """Perform WHOIS lookup on a domain."""
    print_section("WHOIS Lookup")
    try:
        w = whois.whois(domain)
        info = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),
            "name_servers": w.name_servers,
            "registrant_name": getattr(w, "name", None),
            "registrant_org": getattr(w, "org", None),
            "registrant_country": getattr(w, "country", None),
            "registrant_state": getattr(w, "state", None),
            "registrant_email": getattr(w, "emails", None),
            "dnssec": getattr(w, "dnssec", None),
            "status": w.status,
        }

        for key, val in info.items():
            label = key.replace("_", " ").title()
            if val:
                if isinstance(val, list):
                    print_found(label, ", ".join(str(v) for v in val))
                else:
                    print_found(label, str(val))
            else:
                print_not_found(label)

        return {k: v for k, v in info.items() if v}
    except Exception as e:
        print_error(f"WHOIS lookup failed: {e}")
        return {}


# ── DNS Records ────────────────────────────────────────────────────────

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA", "PTR"]


def dns_lookup(domain: str) -> dict:
    """Query all DNS record types for a domain."""
    print_section("DNS Records")
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    table = create_table(
        f"DNS Records for {domain}",
        [("Type", "cyan"), ("Record", "white"), ("TTL", "dim")],
    )

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                records.append(str(rdata))
                table.add_row(rtype, str(rdata), str(answers.rrset.ttl))
            results[rtype] = records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except dns.exception.Timeout:
            pass
        except Exception:
            pass

    if results:
        console.print(table)
    else:
        print_error("No DNS records found")

    return results


# ── SSL Certificate ────────────────────────────────────────────────────

def ssl_info(domain: str, port: int = 443) -> dict:
    """Retrieve SSL/TLS certificate information."""
    print_section("SSL/TLS Certificate")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, port))
            cert = s.getpeercert()

        info = {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "serial_number": cert.get("serialNumber"),
            "version": cert.get("version"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [entry[1] for entry in cert.get("subjectAltName", [])],
        }

        print_found("Subject", json.dumps(info["subject"], indent=2))
        print_found("Issuer", json.dumps(info["issuer"], indent=2))
        print_found("Serial", str(info["serial_number"]))
        print_found("Valid From", str(info["not_before"]))
        print_found("Valid Until", str(info["not_after"]))
        if info["san"]:
            print_found("SANs", ", ".join(info["san"]))

        return info
    except Exception as e:
        print_error(f"SSL lookup failed: {e}")
        return {}
