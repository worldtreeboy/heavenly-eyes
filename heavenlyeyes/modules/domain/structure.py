"""Domain structure — subdomain enumeration and mapping."""

import concurrent.futures
import dns.resolver
from rich.console import Console

from heavenlyeyes.core.utils import print_section, print_found, print_info, create_table, console

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "ntp", "imap", "remote",
    "blog", "webdisk", "ns", "direct", "direct-connect", "proxy", "vpn",
    "admin", "administrator", "api", "app", "apps", "auth", "beta", "cdn",
    "cloud", "cms", "cpanel", "dashboard", "db", "demo", "dev", "developer",
    "docs", "download", "email", "exchange", "files", "forum", "gateway",
    "git", "help", "host", "hosting", "img", "images", "internal", "intranet",
    "jenkins", "jira", "ldap", "login", "m", "manage", "media", "mobile",
    "monitor", "mysql", "new", "news", "noc", "old", "owa", "panel",
    "portal", "preview", "prod", "production", "rdp", "redirect", "registry",
    "relay", "repo", "repository", "s3", "sandbox", "search", "secure",
    "server", "shop", "signin", "signup", "sip", "stage", "staging",
    "static", "status", "store", "support", "test", "testing", "ticket",
    "tracker", "upload", "v2", "vps", "web", "weblog", "wiki", "ww",
    "www2", "www3", "gitlab", "grafana", "kibana", "prometheus", "sentry",
    "sonar", "vault", "consul", "nomad", "k8s", "kubernetes", "docker",
    "rancher", "traefik", "nginx", "apache", "tomcat", "node", "go",
]


def _check_subdomain(sub: str, domain: str) -> tuple[str, str | None]:
    """Check if a subdomain resolves."""
    fqdn = f"{sub}.{domain}"
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    try:
        answers = resolver.resolve(fqdn, "A")
        ip = str(answers[0])
        return (fqdn, ip)
    except Exception:
        return (fqdn, None)


def enumerate_subdomains(domain: str, wordlist: list[str] | None = None, threads: int = 20) -> dict:
    """Enumerate subdomains via DNS brute force."""
    print_section("Subdomain Enumeration")
    subs = wordlist or COMMON_SUBDOMAINS
    print_info(f"Checking {len(subs)} potential subdomains with {threads} threads...")

    found = {}
    table = create_table(
        f"Subdomains for {domain}",
        [("Subdomain", "green"), ("IP Address", "white")],
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_check_subdomain, sub, domain): sub for sub in subs}
        for future in concurrent.futures.as_completed(futures):
            fqdn, ip = future.result()
            if ip:
                found[fqdn] = ip
                table.add_row(fqdn, ip)

    if found:
        console.print(table)
        print_info(f"Found {len(found)} subdomains")
    else:
        print_info("No subdomains discovered")

    return found


def reverse_dns(ip: str) -> str | None:
    """Perform reverse DNS lookup."""
    try:
        result = dns.resolver.resolve_address(ip)
        return str(result[0])
    except Exception:
        return None
