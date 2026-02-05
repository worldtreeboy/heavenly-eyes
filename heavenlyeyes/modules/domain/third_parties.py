"""Third-party service and integration detection."""

import re
from bs4 import BeautifulSoup
from heavenlyeyes.core.utils import (
    print_section, print_found, print_info, create_table, console, make_request,
)

THIRD_PARTY_DOMAINS = {
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "googleapis.com": "Google APIs",
    "gstatic.com": "Google Static",
    "google.com/recaptcha": "Google reCAPTCHA",
    "facebook.net": "Facebook SDK",
    "connect.facebook.net": "Facebook Connect",
    "fbcdn.net": "Facebook CDN",
    "twitter.com/widgets": "Twitter Widgets",
    "platform.twitter.com": "Twitter Platform",
    "cdn.jsdelivr.net": "jsDelivr CDN",
    "cdnjs.cloudflare.com": "Cloudflare CDNJS",
    "unpkg.com": "UNPKG",
    "maxcdn.bootstrapcdn.com": "Bootstrap CDN",
    "code.jquery.com": "jQuery CDN",
    "cdn.shopify.com": "Shopify",
    "js.stripe.com": "Stripe",
    "checkout.stripe.com": "Stripe Checkout",
    "widget.intercom.io": "Intercom",
    "js.intercomcdn.com": "Intercom",
    "static.hotjar.com": "Hotjar",
    "snap.licdn.com": "LinkedIn Insights",
    "bat.bing.com": "Bing Ads",
    "sc-static.net": "Snapchat Pixel",
    "sentry.io": "Sentry",
    "rum.hlx.page": "Adobe Helix",
    "newrelic.com": "New Relic",
    "nr-data.net": "New Relic",
    "segment.io": "Segment",
    "cdn.segment.com": "Segment",
    "api.amplitude.com": "Amplitude",
    "cdn.amplitude.com": "Amplitude",
    "plausible.io": "Plausible Analytics",
    "cdn.mxpnl.com": "Mixpanel",
    "js.hs-scripts.com": "HubSpot",
    "js.hsforms.net": "HubSpot Forms",
    "static.zdassets.com": "Zendesk",
    "ekr.zdassets.com": "Zendesk",
    "assets.calendly.com": "Calendly",
    "embed.typeform.com": "Typeform",
    "maps.googleapis.com": "Google Maps",
    "www.youtube.com/embed": "YouTube Embed",
    "player.vimeo.com": "Vimeo Embed",
}


def detect_third_parties(domain: str) -> dict:
    """Detect third-party services loaded by a domain."""
    print_section("Third-Party Services")

    url = f"https://{domain}"
    resp = make_request(url)
    if not resp:
        url = f"http://{domain}"
        resp = make_request(url)
    if not resp:
        return {}

    found = {}
    body = resp.text

    # Check for third-party domains in page source
    for tp_domain, service in THIRD_PARTY_DOMAINS.items():
        if tp_domain in body:
            if service not in found:
                found[service] = {"domain": tp_domain, "source": "Page source"}

    # Parse script and link tags for external resources
    try:
        soup = BeautifulSoup(body, "lxml")
        for tag in soup.find_all(["script", "link", "img", "iframe"]):
            src = tag.get("src") or tag.get("href") or ""
            if src.startswith(("http://", "https://", "//")):
                for tp_domain, service in THIRD_PARTY_DOMAINS.items():
                    if tp_domain in src and service not in found:
                        found[service] = {"domain": tp_domain, "url": src, "source": "Resource tag"}
    except Exception:
        pass

    if found:
        table = create_table(
            f"Third-Party Services on {domain}",
            [("Service", "green"), ("Domain", "white"), ("Source", "dim")],
        )
        for service, meta in sorted(found.items()):
            table.add_row(service, meta.get("domain", ""), meta.get("source", ""))
        console.print(table)
        print_info(f"Found {len(found)} third-party services")
    else:
        print_info("No third-party services detected")

    return found
