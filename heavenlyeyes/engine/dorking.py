"""Google Dorking Engine — automated advanced search queries."""

import re
import urllib.parse

from heavenlyeyes.engine.stealth import StealthSession, StealthConfig
from heavenlyeyes.engine.confidence import Finding, make_finding
from heavenlyeyes.engine.dashboard import print_phase, print_finding, print_finding, console


DORK_TEMPLATES = {
    # ── Document exposure ──
    "exposed_docs": [
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:doc OR filetype:docx',
        'site:{domain} filetype:xls OR filetype:xlsx',
        'site:{domain} filetype:ppt OR filetype:pptx',
        'site:{domain} filetype:csv',
        'site:{domain} filetype:txt',
    ],
    # ── Configuration / sensitive files ──
    "config_files": [
        'site:{domain} filetype:env OR filetype:yaml OR filetype:yml',
        'site:{domain} filetype:conf OR filetype:cfg OR filetype:ini',
        'site:{domain} filetype:log',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:bak OR filetype:backup',
        'site:{domain} filetype:xml "password"',
        'site:{domain} filetype:json "api_key" OR "apikey" OR "secret"',
    ],
    # ── Directory listings ──
    "directory_listings": [
        'site:{domain} intitle:"index of /"',
        'site:{domain} intitle:"index of" "parent directory"',
        'site:{domain} intitle:"index of" "backup"',
        'site:{domain} intitle:"index of" ".git"',
    ],
    # ── Login / admin panels ──
    "admin_panels": [
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login',
        'site:{domain} inurl:dashboard',
        'site:{domain} inurl:cpanel',
        'site:{domain} intitle:"admin" inurl:panel',
        'site:{domain} inurl:wp-admin OR inurl:wp-login',
    ],
    # ── Sensitive data exposure ──
    "data_exposure": [
        'site:{domain} "password" filetype:txt',
        'site:{domain} "username" "password" filetype:log',
        'site:{domain} "BEGIN RSA PRIVATE KEY"',
        'site:{domain} "BEGIN OPENSSH PRIVATE KEY"',
        'site:{domain} "AKIA" filetype:txt OR filetype:env',  # AWS access key
        'site:{domain} inurl:"/api/v" -inurl:docs',
        'site:{domain} "phpinfo()"',
    ],
    # ── Error messages / debug info ──
    "error_pages": [
        'site:{domain} "Fatal error" OR "Warning:" filetype:php',
        'site:{domain} "stack trace" OR "traceback"',
        'site:{domain} "SQL syntax" OR "mysql_fetch"',
        'site:{domain} intitle:"500 Internal Server Error"',
        'site:{domain} "server at" "port" intitle:Apache',
    ],
    # ── Email / contact harvesting ──
    "emails": [
        'site:{domain} "@{domain}" filetype:pdf OR filetype:doc OR filetype:xls',
        '"{domain}" "@{domain}" -site:{domain}',
        'intext:"@{domain}" filetype:csv OR filetype:txt',
    ],
    # ── Username / person searches ──
    "username_dorks": [
        '"{username}" site:github.com',
        '"{username}" site:linkedin.com',
        '"{username}" site:twitter.com OR site:x.com',
        '"{username}" site:reddit.com',
        '"{username}" site:medium.com',
        '"{username}" site:stackoverflow.com',
        '"{username}" site:pastebin.com',
        '"{username}" "email" OR "contact"',
    ],
    # ── Email-specific dorks ──
    "email_dorks": [
        '"{email}" -site:{email_domain}',
        '"{email}" site:pastebin.com',
        '"{email}" site:github.com',
        '"{email}" filetype:pdf OR filetype:doc',
        '"{email}" "password" OR "passwd" OR "credentials"',
    ],
    # ── Subdomain / infrastructure ──
    "infrastructure": [
        'site:*.{domain} -www',
        'site:{domain} inurl:staging OR inurl:dev OR inurl:test',
        'site:{domain} inurl:api',
        'site:{domain} intitle:"phpMyAdmin"',
        'site:{domain} intitle:"Swagger UI"',
    ],
}


class DorkingEngine:
    """Automated Google Dorking for OSINT recon."""

    def __init__(self, session: StealthSession | None = None):
        self.session = session or StealthSession(
            StealthConfig(min_delay=2.0, max_delay=6.0, verbose=True)
        )

    def generate_dorks(
        self,
        target: str,
        target_type: str = "domain",
        categories: list[str] | None = None,
    ) -> list[dict]:
        """Generate dork queries for a target.

        Returns list of {query, category, search_url} dicts.
        """
        dorks = []
        use_categories = categories or list(DORK_TEMPLATES.keys())

        for cat in use_categories:
            templates = DORK_TEMPLATES.get(cat, [])
            for template in templates:
                # Skip templates that don't match target type
                if target_type == "username" and "{domain}" in template and "{username}" not in template:
                    continue
                if target_type == "email" and "{domain}" in template and "{email}" not in template:
                    continue

                try:
                    if target_type == "domain":
                        query = template.format(domain=target)
                    elif target_type == "username":
                        query = template.format(username=target, domain="")
                    elif target_type == "email":
                        email_domain = target.split("@")[1] if "@" in target else ""
                        query = template.format(
                            email=target,
                            email_domain=email_domain,
                            domain=email_domain,
                        )
                    else:
                        query = template.format(domain=target, username=target, email=target)
                except (KeyError, IndexError):
                    continue

                query = query.strip()
                if query:
                    encoded = urllib.parse.quote_plus(query)
                    dorks.append({
                        "query": query,
                        "category": cat,
                        "search_url": f"https://www.google.com/search?q={encoded}&num=20",
                    })

        return dorks

    def execute_dorks(
        self,
        target: str,
        target_type: str = "domain",
        categories: list[str] | None = None,
        max_dorks: int = 20,
    ) -> list[Finding]:
        """Execute dork queries and parse results."""
        print_phase("Google Dorking Engine", "🔎")

        dorks = self.generate_dorks(target, target_type, categories)[:max_dorks]
        findings = []

        console.print(f"  [dim]Executing {len(dorks)} dork queries with stealth delays...[/dim]")

        for i, dork in enumerate(dorks, 1):
            console.print(
                f"  [dim][{i}/{len(dorks)}][/dim] [cyan]{dork['category']}[/cyan]: "
                f"[white]{dork['query'][:60]}{'...' if len(dork['query']) > 60 else ''}[/white]"
            )

            resp = self.session.get(dork["search_url"])
            if not resp:
                continue

            # Parse Google results
            urls = self._parse_google_results(resp.text, target)

            for url, title in urls:
                finding = make_finding(
                    category=dork["category"],
                    source=f"Google Dork ({dork['category']})",
                    label=title[:60] if title else dork["category"],
                    value=url,
                    source_type="google_dork",
                    pivot_type="url",
                    pivot_value=url,
                    raw_data={"dork_query": dork["query"]},
                )
                findings.append(finding)
                print_finding(finding)

        if findings:
            console.print(f"\n  [green]Dorking found {len(findings)} result(s)[/green]")
        else:
            console.print(f"\n  [dim]No results from dorking (may be rate limited)[/dim]")

        return findings

    def _parse_google_results(self, html: str, target: str) -> list[tuple[str, str]]:
        """Extract URLs and titles from Google search results HTML."""
        results = []
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "lxml")

            for div in soup.select("div.g, div[data-sokoban-container]"):
                link = div.find("a", href=True)
                title_tag = div.find("h3")
                if link and title_tag:
                    url = link["href"]
                    title = title_tag.get_text(strip=True)
                    if url.startswith("http") and "google.com" not in url:
                        results.append((url, title))

            # Fallback: regex extraction if BeautifulSoup finds nothing
            if not results:
                url_pattern = r'href="(https?://(?:(?!google\.com)[^\s"<>])+)"'
                matches = re.findall(url_pattern, html)
                for url in matches[:10]:
                    if target.replace("@", "") in url.lower() or any(
                        kw in url.lower()
                        for kw in ("pastebin", "github", "linkedin", "pdf", "doc")
                    ):
                        results.append((url, ""))

        except Exception:
            pass

        return results[:10]

    def get_dork_report(self, target: str, target_type: str = "domain") -> list[dict]:
        """Generate a report of dork queries without executing them (dry run)."""
        dorks = self.generate_dorks(target, target_type)
        return dorks
