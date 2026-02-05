"""Business investigation — organization, locations, staff, contacts, records, services."""

import re
import json
from bs4 import BeautifulSoup
from heavenlyeyes.core.utils import (
    print_section, print_found, print_not_found, print_info, print_warning,
    print_error, create_table, console, make_request,
)


# ── Organization Info ──────────────────────────────────────────────────

def investigate_organization(domain: str) -> dict:
    """Gather organization information from a domain."""
    print_section("Organization Investigation")

    info = {}

    # Attempt to get org info from the website
    for proto in ("https", "http"):
        resp = make_request(f"{proto}://{domain}")
        if resp:
            try:
                soup = BeautifulSoup(resp.text, "lxml")

                # Title
                title = soup.find("title")
                if title:
                    info["title"] = title.get_text(strip=True)
                    print_found("Site Title", info["title"])

                # Meta description
                desc = soup.find("meta", attrs={"name": "description"})
                if desc and desc.get("content"):
                    info["description"] = desc["content"]
                    print_found("Description", info["description"])

                # Open Graph data
                og_keys = ["og:site_name", "og:title", "og:description", "og:type", "og:url", "og:image"]
                for og in og_keys:
                    tag = soup.find("meta", property=og)
                    if tag and tag.get("content"):
                        key = og.replace("og:", "og_")
                        info[key] = tag["content"]
                        print_found(og, tag["content"])

                # JSON-LD structured data
                for script in soup.find_all("script", type="application/ld+json"):
                    try:
                        ld = json.loads(script.string)
                        if isinstance(ld, dict):
                            org_type = ld.get("@type", "")
                            if org_type in ("Organization", "Corporation", "LocalBusiness", "Company"):
                                if ld.get("name"):
                                    info["org_name"] = ld["name"]
                                    print_found("Organization", ld["name"])
                                if ld.get("url"):
                                    info["org_url"] = ld["url"]
                                if ld.get("logo"):
                                    logo = ld["logo"]
                                    if isinstance(logo, dict):
                                        logo = logo.get("url", "")
                                    info["logo"] = logo
                                    print_found("Logo", str(logo))
                                if ld.get("description"):
                                    info["org_description"] = ld["description"]
                                if ld.get("foundingDate"):
                                    info["founding_date"] = ld["foundingDate"]
                                    print_found("Founded", ld["foundingDate"])
                                if ld.get("numberOfEmployees"):
                                    info["employees"] = str(ld["numberOfEmployees"])
                                    print_found("Employees", str(ld["numberOfEmployees"]))
                    except (json.JSONDecodeError, TypeError):
                        pass

            except Exception as e:
                print_error(f"Parsing error: {e}")
            break

    if not info:
        print_info("Limited organization info found from public pages")

    return info


# ── Location Discovery ─────────────────────────────────────────────────

def discover_locations(domain: str) -> dict:
    """Discover physical locations from a domain."""
    print_section("Location Discovery")

    locations = {}

    for proto in ("https", "http"):
        for path in ("", "/contact", "/about", "/locations", "/contact-us", "/about-us"):
            resp = make_request(f"{proto}://{domain}{path}")
            if not resp:
                continue

            try:
                soup = BeautifulSoup(resp.text, "lxml")

                # JSON-LD structured data
                for script in soup.find_all("script", type="application/ld+json"):
                    try:
                        ld = json.loads(script.string)
                        if isinstance(ld, dict) and ld.get("address"):
                            addr = ld["address"]
                            if isinstance(addr, dict):
                                loc = {
                                    "street": addr.get("streetAddress", ""),
                                    "city": addr.get("addressLocality", ""),
                                    "state": addr.get("addressRegion", ""),
                                    "zip": addr.get("postalCode", ""),
                                    "country": addr.get("addressCountry", ""),
                                }
                                loc_str = ", ".join(v for v in loc.values() if v)
                                if loc_str:
                                    locations[loc_str] = loc
                                    print_found("Address", loc_str)
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Look for addresses in text (US format)
                text = soup.get_text()
                address_pattern = r"\d{1,5}\s+[\w\s.]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl)\b[.,]?\s*(?:Suite|Ste|Apt|Unit|#)?\s*\d*[.,]?\s*\w+[.,]?\s*[A-Z]{2}\s+\d{5}"
                addresses = re.findall(address_pattern, text, re.IGNORECASE)
                for addr in addresses:
                    addr = addr.strip()
                    if addr and addr not in locations:
                        locations[addr] = {"raw": addr}
                        print_found("Address (regex)", addr)

                # Look for Google Maps embeds
                for iframe in soup.find_all("iframe"):
                    src = iframe.get("src", "")
                    if "google.com/maps" in src or "maps.google" in src:
                        locations["google_maps_embed"] = {"embed_url": src}
                        print_found("Google Maps", "Embedded map found")

            except Exception:
                pass

    if not locations:
        print_info("No physical locations discovered from public pages")

    return locations


# ── Staff Discovery ────────────────────────────────────────────────────

def discover_staff(domain: str) -> dict:
    """Discover staff/team members from public pages."""
    print_section("Staff Discovery")

    staff = {}

    for proto in ("https", "http"):
        for path in ("/team", "/about", "/about-us", "/our-team", "/people", "/leadership", "/staff"):
            resp = make_request(f"{proto}://{domain}{path}")
            if not resp or resp.status_code != 200:
                continue

            try:
                soup = BeautifulSoup(resp.text, "lxml")

                # JSON-LD Person data
                for script in soup.find_all("script", type="application/ld+json"):
                    try:
                        ld = json.loads(script.string)
                        items = ld if isinstance(ld, list) else [ld]
                        for item in items:
                            if isinstance(item, dict) and item.get("@type") == "Person":
                                name = item.get("name", "Unknown")
                                person = {
                                    "name": name,
                                    "title": item.get("jobTitle", ""),
                                    "url": item.get("url", ""),
                                    "image": item.get("image", ""),
                                }
                                staff[name] = person
                                role = person["title"] or "Team Member"
                                print_found(role, name)
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Look for common team page patterns
                for card in soup.find_all(class_=re.compile(r"team|staff|member|person|employee", re.I)):
                    name_tag = card.find(re.compile(r"h[2-4]"))
                    if name_tag:
                        name = name_tag.get_text(strip=True)
                        role_tag = card.find(class_=re.compile(r"title|role|position|job", re.I))
                        role = role_tag.get_text(strip=True) if role_tag else ""
                        if name and name not in staff:
                            staff[name] = {"name": name, "title": role}
                            print_found(role or "Team Member", name)

            except Exception:
                pass

    if not staff:
        print_info("No staff members discovered from public pages")

    return staff


# ── Contact Information ────────────────────────────────────────────────

def discover_contacts(domain: str) -> dict:
    """Discover contact information from public pages."""
    print_section("Contact Information")

    contacts = {
        "emails": [],
        "phones": [],
        "social_links": [],
    }

    social_domains = [
        "facebook.com", "twitter.com", "x.com", "linkedin.com", "instagram.com",
        "youtube.com", "tiktok.com", "github.com", "pinterest.com",
    ]

    for proto in ("https", "http"):
        for path in ("", "/contact", "/about", "/contact-us"):
            resp = make_request(f"{proto}://{domain}{path}")
            if not resp:
                continue

            text = resp.text

            # Emails
            emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)
            contacts["emails"].extend(e.lower() for e in emails)

            # Phone numbers
            phones = re.findall(
                r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}",
                text,
            )
            contacts["phones"].extend(phones)

            # Social links
            try:
                soup = BeautifulSoup(text, "lxml")
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    for sd in social_domains:
                        if sd in href:
                            contacts["social_links"].append(href)
            except Exception:
                pass

    # Deduplicate
    contacts["emails"] = sorted(set(contacts["emails"]))
    contacts["phones"] = sorted(set(contacts["phones"]))[:10]  # Limit phone matches
    contacts["social_links"] = sorted(set(contacts["social_links"]))

    if contacts["emails"]:
        for e in contacts["emails"]:
            print_found("Email", e)
    if contacts["phones"]:
        for p in contacts["phones"]:
            print_found("Phone", p)
    if contacts["social_links"]:
        for s in contacts["social_links"]:
            print_found("Social", s)
    if not any(contacts.values()):
        print_info("No contact information discovered")

    return contacts


# ── Business Records ───────────────────────────────────────────────────

def investigate_records(domain: str) -> dict:
    """Look for business record indicators."""
    print_section("Business Records")

    records = {}

    for proto in ("https", "http"):
        resp = make_request(f"{proto}://{domain}")
        if not resp:
            continue

        try:
            soup = BeautifulSoup(resp.text, "lxml")

            # Footer often has business info
            footer = soup.find("footer")
            if footer:
                footer_text = footer.get_text()

                # Copyright notice
                copyright_match = re.findall(
                    r"(?:©|copyright)\s*(\d{4})?\s*[-–]?\s*(\d{4})?\s*(.*?)(?:\.|All rights|$)",
                    footer_text,
                    re.IGNORECASE,
                )
                if copyright_match:
                    for m in copyright_match:
                        year = m[1] or m[0]
                        entity = m[2].strip()
                        if entity:
                            records["copyright_entity"] = entity
                            records["copyright_year"] = year
                            print_found("Copyright", f"{entity} ({year})")

                # Business registration numbers
                reg_patterns = {
                    "VAT": r"(?:VAT|BTW|TVA|USt)\s*(?:No\.?|Number|ID)?[:\s]*([A-Z]{2}\d{8,12})",
                    "Company Reg": r"(?:Company|Registration|Reg)\s*(?:No\.?|Number)?[:\s]*(\d{6,10})",
                    "EIN": r"(?:EIN|Tax\s*ID)[:\s]*(\d{2}-\d{7})",
                }
                for label, pattern in reg_patterns.items():
                    match = re.search(pattern, footer_text, re.IGNORECASE)
                    if match:
                        records[label.lower().replace(" ", "_")] = match.group(1)
                        print_found(label, match.group(1))

            # Terms of service / Privacy policy links
            for a in soup.find_all("a", href=True):
                href_lower = a["href"].lower()
                text_lower = a.get_text(strip=True).lower()
                if any(kw in href_lower or kw in text_lower for kw in ("terms", "tos", "terms-of-service")):
                    records["terms_url"] = a["href"]
                    print_found("Terms of Service", a["href"])
                if any(kw in href_lower or kw in text_lower for kw in ("privacy", "privacy-policy")):
                    records["privacy_url"] = a["href"]
                    print_found("Privacy Policy", a["href"])

        except Exception:
            pass
        break

    if not records:
        print_info("No business records discovered from public pages")

    return records


# ── Services Discovery ─────────────────────────────────────────────────

def discover_services(domain: str) -> dict:
    """Discover services/products offered by the organization."""
    print_section("Services Discovery")

    services = {}

    for proto in ("https", "http"):
        for path in ("", "/services", "/products", "/solutions", "/features", "/pricing"):
            resp = make_request(f"{proto}://{domain}{path}")
            if not resp or resp.status_code != 200:
                continue

            try:
                soup = BeautifulSoup(resp.text, "lxml")

                # JSON-LD services
                for script in soup.find_all("script", type="application/ld+json"):
                    try:
                        ld = json.loads(script.string)
                        items = ld if isinstance(ld, list) else [ld]
                        for item in items:
                            if isinstance(item, dict) and item.get("@type") in ("Service", "Product", "SoftwareApplication"):
                                name = item.get("name", "")
                                if name:
                                    services[name] = {
                                        "type": item["@type"],
                                        "description": item.get("description", ""),
                                        "url": item.get("url", ""),
                                    }
                                    print_found(item["@type"], name)
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Common service listing patterns
                if path in ("/services", "/products", "/solutions", "/features"):
                    for heading in soup.find_all(re.compile(r"h[2-3]")):
                        text = heading.get_text(strip=True)
                        if text and len(text) < 100:
                            services[text] = {"source": path}
                            print_found("Service/Product", text)

            except Exception:
                pass

    if not services:
        print_info("No specific services/products discovered")

    return services
