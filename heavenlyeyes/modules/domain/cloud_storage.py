"""Cloud storage bucket/blob discovery."""

import requests
from heavenlyeyes.core.utils import (
    print_section, print_found, print_not_found, print_info, print_warning,
    create_table, console, make_request,
)

CLOUD_PATTERNS = {
    "AWS S3": [
        "https://{name}.s3.amazonaws.com",
        "https://s3.amazonaws.com/{name}",
    ],
    "Azure Blob": [
        "https://{name}.blob.core.windows.net",
    ],
    "Google Cloud Storage": [
        "https://storage.googleapis.com/{name}",
        "https://{name}.storage.googleapis.com",
    ],
    "DigitalOcean Spaces": [
        "https://{name}.nyc3.digitaloceanspaces.com",
        "https://{name}.ams3.digitaloceanspaces.com",
        "https://{name}.sgp1.digitaloceanspaces.com",
    ],
    "Firebase": [
        "https://{name}.firebaseio.com/.json",
    ],
}


def check_cloud_storage(domain: str) -> dict:
    """Check for exposed cloud storage buckets related to a domain."""
    print_section("Cloud Storage Discovery")

    base = domain.replace(".", "-")
    names_to_check = [
        base,
        base.replace("-", ""),
        domain.split(".")[0],
        f"{domain.split('.')[0]}-assets",
        f"{domain.split('.')[0]}-backup",
        f"{domain.split('.')[0]}-data",
        f"{domain.split('.')[0]}-dev",
        f"{domain.split('.')[0]}-staging",
        f"{domain.split('.')[0]}-prod",
        f"{domain.split('.')[0]}-public",
        f"{domain.split('.')[0]}-private",
        f"{domain.split('.')[0]}-uploads",
        f"{domain.split('.')[0]}-media",
        f"{domain.split('.')[0]}-static",
        f"{domain.split('.')[0]}-logs",
    ]

    found = {}
    table = create_table(
        "Cloud Storage Findings",
        [("Provider", "cyan"), ("Bucket Name", "white"), ("Status", "yellow")],
    )

    print_info(f"Checking {len(names_to_check)} bucket name variations across cloud providers...")

    for provider, patterns in CLOUD_PATTERNS.items():
        for name in names_to_check:
            for pattern in patterns:
                url = pattern.format(name=name)
                try:
                    resp = requests.head(url, timeout=5, allow_redirects=False)
                    status = resp.status_code
                    if status in (200, 403):
                        status_text = "PUBLIC" if status == 200 else "EXISTS (403)"
                        found[url] = {
                            "provider": provider,
                            "name": name,
                            "status": status_text,
                            "url": url,
                        }
                        table.add_row(provider, name, f"[{'red' if status == 200 else 'yellow'}]{status_text}[/]")
                except requests.RequestException:
                    pass

    if found:
        console.print(table)
        if any(f["status"] == "PUBLIC" for f in found.values()):
            print_warning("PUBLIC buckets found! These may expose sensitive data.")
    else:
        print_info("No cloud storage buckets discovered")

    return found
