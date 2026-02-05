"""Technology detection — identify frameworks, servers, and services."""

import re
from bs4 import BeautifulSoup

from heavenlyeyes.core.utils import (
    print_section, print_found, print_info, create_table, console, make_request,
)

HEADER_SIGNATURES = {
    "Server": {
        "nginx": "Nginx",
        "apache": "Apache",
        "cloudflare": "Cloudflare",
        "microsoft-iis": "Microsoft IIS",
        "litespeed": "LiteSpeed",
        "openresty": "OpenResty",
        "gunicorn": "Gunicorn",
        "uvicorn": "Uvicorn",
        "caddy": "Caddy",
    },
    "X-Powered-By": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Express.js (Node)",
        "next.js": "Next.js",
        "nuxt": "Nuxt.js",
        "flask": "Flask",
        "django": "Django",
        "ruby": "Ruby on Rails",
        "java": "Java",
    },
}

HTML_SIGNATURES = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "Joomla": "Joomla",
    "drupal": "Drupal",
    "shopify": "Shopify",
    "squarespace": "Squarespace",
    "wix.com": "Wix",
    "react": "React",
    "vue": "Vue.js",
    "angular": "Angular",
    "svelte": "Svelte",
    "next": "Next.js",
    "nuxt": "Nuxt.js",
    "gatsby": "Gatsby",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "tailwind": "Tailwind CSS",
    "cloudflare": "Cloudflare",
    "google-analytics": "Google Analytics",
    "gtag": "Google Tag Manager",
    "hotjar": "Hotjar",
    "recaptcha": "Google reCAPTCHA",
    "stripe": "Stripe",
    "intercom": "Intercom",
    "zendesk": "Zendesk",
    "hubspot": "HubSpot",
    "facebook pixel": "Facebook Pixel",
    "fb-pixel": "Facebook Pixel",
    "matomo": "Matomo Analytics",
}

META_SIGNATURES = {
    "generator": {
        "wordpress": "WordPress",
        "joomla": "Joomla",
        "drupal": "Drupal",
        "ghost": "Ghost CMS",
        "hugo": "Hugo",
        "jekyll": "Jekyll",
        "hexo": "Hexo",
        "gatsby": "Gatsby",
    },
}


def detect_technologies(domain: str) -> dict:
    """Detect technologies used by a domain."""
    print_section("Technology Detection")

    url = f"https://{domain}"
    resp = make_request(url)
    if not resp:
        url = f"http://{domain}"
        resp = make_request(url)
    if not resp:
        return {}

    technologies = {}

    # ── Analyze headers ──
    for header_name, sigs in HEADER_SIGNATURES.items():
        val = resp.headers.get(header_name, "").lower()
        if val:
            for sig, tech in sigs.items():
                if sig in val:
                    technologies[tech] = {"source": f"Header: {header_name}", "value": resp.headers[header_name]}

    # CDN / Security headers
    if "cf-ray" in resp.headers:
        technologies["Cloudflare CDN"] = {"source": "Header: CF-Ray"}
    if "x-amz" in str(resp.headers).lower():
        technologies["AWS"] = {"source": "Header: X-Amz"}
    if "x-vercel" in str(resp.headers).lower():
        technologies["Vercel"] = {"source": "Header: X-Vercel"}
    if "x-netlify" in str(resp.headers).lower():
        technologies["Netlify"] = {"source": "Header: X-Netlify"}

    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "X-Frame-Options": "X-Frame-Options",
        "X-XSS-Protection": "X-XSS-Protection",
    }
    sec_found = []
    for hdr, name in security_headers.items():
        if hdr in resp.headers:
            sec_found.append(name)
    if sec_found:
        technologies["Security Headers"] = {"source": "Headers", "value": ", ".join(sec_found)}

    # ── Analyze HTML ──
    body = resp.text.lower()
    for sig, tech in HTML_SIGNATURES.items():
        if sig.lower() in body:
            if tech not in technologies:
                technologies[tech] = {"source": "HTML body"}

    # ── Analyze meta tags ──
    try:
        soup = BeautifulSoup(resp.text, "lxml")
        for meta in soup.find_all("meta"):
            name = (meta.get("name") or "").lower()
            content = (meta.get("content") or "").lower()
            if name in META_SIGNATURES:
                for sig, tech in META_SIGNATURES[name].items():
                    if sig in content:
                        technologies[tech] = {"source": f"Meta: {name}", "value": content}
    except Exception:
        pass

    # ── Display results ──
    if technologies:
        table = create_table(
            f"Technologies on {domain}",
            [("Technology", "green"), ("Detection Source", "dim"), ("Details", "white")],
        )
        for tech, meta in sorted(technologies.items()):
            table.add_row(tech, meta.get("source", ""), meta.get("value", ""))
        console.print(table)
    else:
        print_info("No technologies detected")

    return technologies
