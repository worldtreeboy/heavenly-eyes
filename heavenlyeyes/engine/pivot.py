"""Recursive Pivot Engine — takes a single input and branches out automatically."""

import re
import concurrent.futures
from dataclasses import dataclass, field

import dns.resolver
import requests

from heavenlyeyes.engine.stealth import StealthSession, StealthConfig
from heavenlyeyes.engine.confidence import Finding, make_finding
from heavenlyeyes.engine.dorking import DorkingEngine
from heavenlyeyes.engine.synthesis import AISynthesizer
from heavenlyeyes.engine.dashboard import (
    console, print_phase, print_finding, print_pivot_branch,
    build_findings_table, build_summary_panel, create_progress,
    print_banner, print_disclaimer, print_target_info,
)
from heavenlyeyes.core.config import get_api_key
from heavenlyeyes.core.reporter import ReportCollector


# ── Input type detection ───────────────────────────────────────────────

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
PHONE_RE = re.compile(r"^\+?\d{7,15}$")


def classify_input(value: str) -> str:
    """Classify input as email, domain, ip, phone, or username."""
    value = value.strip()
    if EMAIL_RE.match(value):
        return "email"
    if IP_RE.match(value):
        return "ip"
    if DOMAIN_RE.match(value):
        return "domain"
    if PHONE_RE.match(value.replace("-", "").replace(" ", "")):
        return "phone"
    return "username"


# ── Social platform definitions for username pivot ─────────────────────

SOCIAL_PLATFORMS = {
    "GitHub": {"url": "https://api.github.com/users/{u}", "check": "api_json", "api": True},
    "Twitter/X": {"url": "https://x.com/{u}", "check": "status"},
    "Instagram": {"url": "https://www.instagram.com/{u}/", "check": "status"},
    "Reddit": {"url": "https://www.reddit.com/user/{u}/about.json", "check": "api_json", "api": True},
    "LinkedIn": {"url": "https://www.linkedin.com/in/{u}", "check": "status"},
    "TikTok": {"url": "https://www.tiktok.com/@{u}", "check": "status"},
    "YouTube": {"url": "https://www.youtube.com/@{u}", "check": "status"},
    "Twitch": {"url": "https://www.twitch.tv/{u}", "check": "status"},
    "GitLab": {"url": "https://gitlab.com/{u}", "check": "status"},
    "Medium": {"url": "https://medium.com/@{u}", "check": "status"},
    "Dev.to": {"url": "https://dev.to/api/users/by_username?url={u}", "check": "api_json", "api": True},
    "Keybase": {"url": "https://keybase.io/{u}", "check": "status"},
    "HackerOne": {"url": "https://hackerone.com/{u}", "check": "status"},
    "Steam": {"url": "https://steamcommunity.com/id/{u}", "check": "status"},
    "Pinterest": {"url": "https://www.pinterest.com/{u}/", "check": "status"},
    "SoundCloud": {"url": "https://soundcloud.com/{u}", "check": "status"},
    "Mastodon": {"url": "https://mastodon.social/@{u}", "check": "status"},
    "Docker Hub": {"url": "https://hub.docker.com/u/{u}", "check": "status"},
    "npm": {"url": "https://www.npmjs.com/~{u}", "check": "status"},
    "PyPI": {"url": "https://pypi.org/user/{u}/", "check": "status"},
    "Telegram": {"url": "https://t.me/{u}", "check": "status"},
    "Patreon": {"url": "https://www.patreon.com/{u}", "check": "status"},
    "Substack": {"url": "https://{u}.substack.com", "check": "status"},
    "Spotify": {"url": "https://open.spotify.com/user/{u}", "check": "status"},
    "Gravatar": {"url": "https://en.gravatar.com/{u}.json", "check": "api_json", "api": True},
    "HackerNews": {"url": "https://hacker-news.firebaseio.com/v0/user/{u}.json", "check": "api_json", "api": True},
    "StackOverflow": {"url": "https://api.stackexchange.com/2.3/users?inname={u}&site=stackoverflow", "check": "api_json", "api": True},
    "Bitbucket": {"url": "https://bitbucket.org/{u}/", "check": "status"},
    "About.me": {"url": "https://about.me/{u}", "check": "status"},
    "Flickr": {"url": "https://www.flickr.com/people/{u}", "check": "status"},
}


# ── Recursive Pivot Engine ─────────────────────────────────────────────

@dataclass
class PivotNode:
    """A node in the pivot graph."""
    input_type: str
    value: str
    depth: int
    parent: str = ""
    findings: list[Finding] = field(default_factory=list)


class RecursivePivotEngine:
    """Takes a single input and recursively pivots to discover connected intelligence."""

    def __init__(
        self,
        max_depth: int = 2,
        enable_dorking: bool = True,
        enable_ai: bool = True,
        stealth_config: StealthConfig | None = None,
    ):
        self.max_depth = max_depth
        self.enable_dorking = enable_dorking
        self.enable_ai = enable_ai
        self.session = StealthSession(stealth_config or StealthConfig())
        self.dorking = DorkingEngine(self.session)
        self.synthesizer = AISynthesizer()
        self.all_findings: list[Finding] = []
        self.explored: set[str] = set()
        self.pivot_count = 0

    def run(self, target: str, output_dir: str | None = None, html: bool = False) -> list[Finding]:
        """Execute the full recursive pivot scan."""
        print_banner()
        print_disclaimer()

        input_type = classify_input(target)
        print_target_info(input_type, target, self.max_depth)

        # Start recursive pivoting
        root = PivotNode(input_type=input_type, value=target, depth=0)
        self._pivot(root)

        # Google Dorking phase
        if self.enable_dorking:
            dork_findings = self.dorking.execute_dorks(
                target, target_type=input_type, max_dorks=15
            )
            self.all_findings.extend(dork_findings)

        # Display full findings table
        if self.all_findings:
            console.print()
            console.print(build_findings_table(self.all_findings, f"All Findings — {target}"))

        # Summary panel
        categories = {}
        for f in self.all_findings:
            categories[f.category] = categories.get(f.category, 0) + 1
        avg_conf = (
            sum(f.confidence for f in self.all_findings) / len(self.all_findings)
            if self.all_findings else 0
        )
        risk = min(100, len(self.all_findings) * 3 + len([f for f in self.all_findings if f.confidence >= 75]) * 5)

        console.print()
        console.print(build_summary_panel(
            target, len(self.all_findings), self.pivot_count, categories, avg_conf, risk,
        ))

        # AI Synthesis
        if self.enable_ai and self.all_findings:
            self.synthesizer.display_synthesis(target, self.all_findings)

        # Save report
        report = ReportCollector(target)
        report.add_section("pivot_findings", {
            "total": len(self.all_findings),
            "pivots_explored": self.pivot_count,
            "findings": [
                {
                    "category": f.category,
                    "label": f.label,
                    "value": f.value,
                    "confidence": f.confidence,
                    "source": f.source,
                }
                for f in self.all_findings
            ],
        })
        report.save_json(output_dir)
        if html:
            report.save_html(output_dir)

        return self.all_findings

    def _pivot(self, node: PivotNode):
        """Recursively explore a pivot node."""
        key = f"{node.input_type}:{node.value}"
        if key in self.explored:
            return
        self.explored.add(key)
        self.pivot_count += 1

        print_pivot_branch(node.depth, node.input_type, node.value)

        # Execute recon based on input type
        findings = self._recon(node)
        node.findings = findings
        self.all_findings.extend(findings)

        # Extract new pivots from findings
        if node.depth < self.max_depth:
            for f in findings:
                if f.pivot_type and f.pivot_value:
                    child_key = f"{f.pivot_type}:{f.pivot_value}"
                    if child_key not in self.explored:
                        child = PivotNode(
                            input_type=f.pivot_type,
                            value=f.pivot_value,
                            depth=node.depth + 1,
                            parent=node.value,
                        )
                        self._pivot(child)

    def _recon(self, node: PivotNode) -> list[Finding]:
        """Run reconnaissance based on input type."""
        if node.input_type == "username":
            return self._recon_username(node)
        elif node.input_type == "email":
            return self._recon_email(node)
        elif node.input_type == "domain":
            return self._recon_domain(node)
        elif node.input_type == "ip":
            return self._recon_ip(node)
        return []

    # ── Username Recon ─────────────────────────────────────────────────

    def _recon_username(self, node: PivotNode) -> list[Finding]:
        """Discover social profiles and extract pivotable data."""
        print_phase(f"Username Recon: {node.value}", "👤")
        findings = []
        username = node.value

        def check_platform(name, info):
            url = info["url"].format(u=username)
            try:
                if info.get("api") and info["check"] == "api_json":
                    resp = self.session.get(url)
                    if resp and resp.status_code == 200:
                        try:
                            data = resp.json()
                            # Validate it's a real result
                            if isinstance(data, dict) and not data.get("error"):
                                return self._process_api_profile(name, url, data, username)
                        except Exception:
                            pass
                else:
                    resp = self.session.get(url)
                    if resp and resp.status_code == 200:
                        return make_finding(
                            category="social_profile",
                            source=name,
                            label=f"{name} Profile",
                            value=url,
                            source_type="http_status_200",
                            pivot_type="",
                            pivot_value="",
                        )
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = {
                pool.submit(check_platform, name, info): name
                for name, info in SOCIAL_PLATFORMS.items()
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    if isinstance(result, list):
                        for f in result:
                            findings.append(f)
                            print_finding(f)
                    else:
                        findings.append(result)
                        print_finding(result)

        console.print(f"  [dim]Found {len(findings)} profile(s) across {len(SOCIAL_PLATFORMS)} platforms[/dim]")
        return findings

    def _process_api_profile(self, platform: str, url: str, data: dict, username: str) -> list[Finding]:
        """Extract rich data from API responses and generate pivot findings."""
        findings = []

        profile = make_finding(
            category="social_profile",
            source=f"{platform} API",
            label=f"{platform} Profile",
            value=url,
            source_type="api_verified",
            modifiers={"authenticated": False, "exact_match": True},
        )
        findings.append(profile)

        # GitHub-specific enrichment
        if platform == "GitHub" and isinstance(data, dict):
            if data.get("name"):
                findings.append(make_finding(
                    category="identity", source="GitHub API", label="Real Name",
                    value=data["name"], source_type="api_verified",
                ))
            if data.get("email"):
                findings.append(make_finding(
                    category="email", source="GitHub API", label="GitHub Email",
                    value=data["email"], source_type="api_verified",
                    pivot_type="email", pivot_value=data["email"],
                ))
            if data.get("blog"):
                blog = data["blog"]
                if not blog.startswith("http"):
                    blog = f"https://{blog}"
                findings.append(make_finding(
                    category="domain", source="GitHub API", label="Website/Blog",
                    value=blog, source_type="api_verified",
                    pivot_type="domain",
                    pivot_value=re.sub(r"https?://", "", blog).split("/")[0],
                ))
            if data.get("company"):
                findings.append(make_finding(
                    category="organization", source="GitHub API", label="Company",
                    value=data["company"], source_type="api_verified",
                ))
            if data.get("location"):
                findings.append(make_finding(
                    category="location", source="GitHub API", label="Location",
                    value=data["location"], source_type="api_verified",
                ))
            if data.get("bio"):
                findings.append(make_finding(
                    category="identity", source="GitHub API", label="Bio",
                    value=data["bio"][:100], source_type="api_verified",
                ))
            if data.get("twitter_username"):
                findings.append(make_finding(
                    category="social_profile", source="GitHub API", label="Twitter/X",
                    value=f"https://x.com/{data['twitter_username']}",
                    source_type="api_verified",
                    pivot_type="username", pivot_value=data["twitter_username"],
                ))

        # Reddit enrichment
        if platform == "Reddit" and isinstance(data, dict):
            rd = data.get("data", data)
            if rd.get("name"):
                findings.append(make_finding(
                    category="identity", source="Reddit API", label="Reddit Account",
                    value=f"u/{rd['name']}, karma: {rd.get('total_karma', '?')}",
                    source_type="api_verified",
                ))

        # Gravatar enrichment
        if platform == "Gravatar" and isinstance(data, dict):
            entry = data.get("entry", [{}])[0] if data.get("entry") else {}
            if entry.get("displayName"):
                findings.append(make_finding(
                    category="identity", source="Gravatar", label="Display Name",
                    value=entry["displayName"], source_type="api_verified",
                ))
            for account in entry.get("accounts", []):
                findings.append(make_finding(
                    category="social_profile", source="Gravatar", label=account.get("shortname", "Profile"),
                    value=account.get("url", ""), source_type="api_verified",
                ))

        # HackerNews enrichment
        if platform == "HackerNews" and isinstance(data, dict):
            if data.get("about"):
                findings.append(make_finding(
                    category="identity", source="HackerNews", label="HN About",
                    value=data["about"][:100], source_type="api_verified",
                ))

        return findings

    # ── Email Recon ────────────────────────────────────────────────────

    def _recon_email(self, node: PivotNode) -> list[Finding]:
        """Investigate an email address."""
        print_phase(f"Email Recon: {node.value}", "📧")
        findings = []
        email = node.value
        domain = email.split("@")[1]

        # MX validation
        try:
            mx = dns.resolver.resolve(domain, "MX")
            mx_records = [str(r.exchange).rstrip(".") for r in mx]
            findings.append(make_finding(
                category="email", source="DNS MX", label="MX Records",
                value=", ".join(mx_records), source_type="dns_record",
            ))
            print_finding(findings[-1])
        except Exception:
            pass

        # Domain pivot
        findings.append(make_finding(
            category="domain", source="Email Domain", label="Email Domain",
            value=domain, source_type="inference",
            pivot_type="domain", pivot_value=domain,
        ))
        print_finding(findings[-1])

        # Username pivot (local part)
        local = email.split("@")[0]
        findings.append(make_finding(
            category="identity", source="Email Local Part", label="Possible Username",
            value=local, source_type="inference",
            pivot_type="username", pivot_value=local,
        ))
        print_finding(findings[-1])

        # Breach check
        breach_findings = self._check_breaches(email)
        findings.extend(breach_findings)

        # Gravatar check
        import hashlib
        email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
        resp = self.session.get(f"https://en.gravatar.com/{email_hash}.json")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                entry = data.get("entry", [{}])[0]
                if entry:
                    findings.append(make_finding(
                        category="social_profile", source="Gravatar",
                        label="Gravatar Profile",
                        value=f"https://gravatar.com/{email_hash}",
                        source_type="api_verified",
                    ))
                    print_finding(findings[-1])
                    for account in entry.get("accounts", []):
                        findings.append(make_finding(
                            category="social_profile", source="Gravatar",
                            label=account.get("shortname", "Profile"),
                            value=account.get("url", ""),
                            source_type="api_verified",
                        ))
                        print_finding(findings[-1])
            except Exception:
                pass

        return findings

    def _check_breaches(self, email: str) -> list[Finding]:
        """Check email against breach databases."""
        findings = []

        # XposedOrNot (free, no key needed)
        resp = self.session.get(f"https://api.xposedornot.com/v1/check-email/{email}")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("breaches"):
                    breaches = data["breaches"]
                    for b in (breaches if isinstance(breaches, list) else [breaches])[:5]:
                        findings.append(make_finding(
                            category="breach", source="XposedOrNot",
                            label="Breach Found",
                            value=str(b),
                            source_type="breach_data",
                        ))
                        print_finding(findings[-1])
            except Exception:
                pass

        # HIBP (if key available)
        hibp_key = get_api_key("haveibeenpwned")
        if hibp_key:
            resp = self.session.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"hibp-api-key": hibp_key},
            )
            if resp and resp.status_code == 200:
                for b in resp.json()[:10]:
                    findings.append(make_finding(
                        category="breach", source="HaveIBeenPwned",
                        label=b.get("Name", "Breach"),
                        value=f"{b.get('BreachDate', '?')} — {', '.join(b.get('DataClasses', [])[:3])}",
                        source_type="breach_data",
                        modifiers={"authenticated": True},
                    ))
                    print_finding(findings[-1])

        return findings

    # ── Domain Recon ───────────────────────────────────────────────────

    def _recon_domain(self, node: PivotNode) -> list[Finding]:
        """Investigate a domain — DNS, WHOIS, tech, emails."""
        print_phase(f"Domain Recon: {node.value}", "🌐")
        findings = []
        domain = node.value

        # DNS records
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for r in answers:
                    val = str(r).rstrip(".")
                    f = make_finding(
                        category="dns", source=f"DNS {rtype}",
                        label=f"{rtype} Record", value=val,
                        source_type="dns_record",
                    )
                    # MX records can pivot to subdomains/IPs
                    if rtype == "MX":
                        f.pivot_type = "domain"
                        f.pivot_value = val.split()[-1] if " " in val else val
                    findings.append(f)
                    print_finding(f)
            except Exception:
                pass

        # WHOIS
        try:
            import whois
            w = whois.whois(domain)
            if w.registrar:
                findings.append(make_finding(
                    category="domain", source="WHOIS", label="Registrar",
                    value=str(w.registrar), source_type="whois_record",
                ))
                print_finding(findings[-1])
            if getattr(w, "emails", None):
                emails = w.emails if isinstance(w.emails, list) else [w.emails]
                for e in emails:
                    findings.append(make_finding(
                        category="email", source="WHOIS", label="Registrant Email",
                        value=e, source_type="whois_record",
                        pivot_type="email", pivot_value=e,
                    ))
                    print_finding(findings[-1])
            if getattr(w, "org", None):
                findings.append(make_finding(
                    category="organization", source="WHOIS", label="Organization",
                    value=str(w.org), source_type="whois_record",
                ))
                print_finding(findings[-1])
            if w.creation_date:
                findings.append(make_finding(
                    category="domain", source="WHOIS", label="Created",
                    value=str(w.creation_date), source_type="whois_record",
                ))
                print_finding(findings[-1])
        except Exception:
            pass

        # Tech detection (lightweight)
        resp = self.session.get(f"https://{domain}")
        if resp:
            server = resp.headers.get("Server", "")
            if server:
                findings.append(make_finding(
                    category="technology", source="HTTP Header",
                    label="Server", value=server, source_type="html_scrape",
                ))
                print_finding(findings[-1])
            powered = resp.headers.get("X-Powered-By", "")
            if powered:
                findings.append(make_finding(
                    category="technology", source="HTTP Header",
                    label="Powered By", value=powered, source_type="html_scrape",
                ))
                print_finding(findings[-1])

            # Harvest emails from page
            emails = set(re.findall(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                resp.text,
            ))
            for e in list(emails)[:10]:
                findings.append(make_finding(
                    category="email", source="Page Scrape", label="Email Found",
                    value=e, source_type="html_scrape",
                    pivot_type="email", pivot_value=e,
                ))
                print_finding(findings[-1])

        return findings

    # ── IP Recon ───────────────────────────────────────────────────────

    def _recon_ip(self, node: PivotNode) -> list[Finding]:
        """Investigate an IP address."""
        print_phase(f"IP Recon: {node.value}", "🖥️")
        findings = []
        ip = node.value

        # Reverse DNS
        try:
            result = dns.resolver.resolve_address(ip)
            hostname = str(result[0]).rstrip(".")
            findings.append(make_finding(
                category="dns", source="Reverse DNS", label="PTR Record",
                value=hostname, source_type="dns_record",
                pivot_type="domain", pivot_value=hostname,
            ))
            print_finding(findings[-1])
        except Exception:
            pass

        # IP geolocation (free API)
        resp = self.session.get(f"http://ip-api.com/json/{ip}")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("status") == "success":
                    if data.get("org"):
                        findings.append(make_finding(
                            category="organization", source="IP Geolocation",
                            label="Organization", value=data["org"],
                            source_type="api_verified",
                        ))
                        print_finding(findings[-1])
                    if data.get("isp"):
                        findings.append(make_finding(
                            category="infrastructure", source="IP Geolocation",
                            label="ISP", value=data["isp"],
                            source_type="api_verified",
                        ))
                        print_finding(findings[-1])
                    loc_parts = [data.get("city"), data.get("regionName"), data.get("country")]
                    loc = ", ".join(p for p in loc_parts if p)
                    if loc:
                        findings.append(make_finding(
                            category="location", source="IP Geolocation",
                            label="Location", value=loc,
                            source_type="api_verified",
                        ))
                        print_finding(findings[-1])
            except Exception:
                pass

        # Shodan host lookup
        shodan_key = get_api_key("shodan")
        if shodan_key:
            resp = self.session.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": shodan_key},
            )
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    ports = data.get("ports", [])
                    if ports:
                        findings.append(make_finding(
                            category="infrastructure", source="Shodan",
                            label="Open Ports", value=", ".join(str(p) for p in ports[:15]),
                            source_type="shodan_verified",
                        ))
                        print_finding(findings[-1])
                    for hostname in data.get("hostnames", []):
                        findings.append(make_finding(
                            category="domain", source="Shodan", label="Hostname",
                            value=hostname, source_type="shodan_verified",
                            pivot_type="domain", pivot_value=hostname,
                        ))
                        print_finding(findings[-1])
                    vulns = data.get("vulns", [])
                    if vulns:
                        findings.append(make_finding(
                            category="vulnerability", source="Shodan",
                            label="Vulnerabilities",
                            value=", ".join(vulns[:10]),
                            source_type="shodan_verified",
                        ))
                        print_finding(findings[-1])
                except Exception:
                    pass

        return findings
