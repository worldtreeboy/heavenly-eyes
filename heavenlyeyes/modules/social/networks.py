"""Social network username search and profile discovery."""

import concurrent.futures
import requests
from heavenlyeyes.core.utils import (
    print_section, print_found, print_not_found, print_info,
    create_table, console,
)
from heavenlyeyes.core.config import get_timeout

PLATFORMS = {
    "GitHub": {
        "url": "https://github.com/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Twitter/X": {
        "url": "https://x.com/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Instagram": {
        "url": "https://www.instagram.com/{username}/",
        "check": "status_code",
        "valid": 200,
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{username}",
        "check": "status_code",
        "valid": 200,
    },
    "YouTube": {
        "url": "https://www.youtube.com/@{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{username}/",
        "check": "status_code",
        "valid": 200,
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "GitLab": {
        "url": "https://gitlab.com/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Bitbucket": {
        "url": "https://bitbucket.org/{username}/",
        "check": "status_code",
        "valid": 200,
    },
    "Medium": {
        "url": "https://medium.com/@{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Dev.to": {
        "url": "https://dev.to/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Keybase": {
        "url": "https://keybase.io/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "HackerOne": {
        "url": "https://hackerone.com/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Spotify": {
        "url": "https://open.spotify.com/user/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Mastodon (mastodon.social)": {
        "url": "https://mastodon.social/@{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Gravatar": {
        "url": "https://en.gravatar.com/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "About.me": {
        "url": "https://about.me/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "HackerNews": {
        "url": "https://news.ycombinator.com/user?id={username}",
        "check": "text_absent",
        "invalid_text": "No such user.",
    },
    "StackOverflow": {
        "url": "https://stackoverflow.com/users/?tab=accounts&SearchText={username}",
        "check": "status_code",
        "valid": 200,
    },
    "Docker Hub": {
        "url": "https://hub.docker.com/u/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "npm": {
        "url": "https://www.npmjs.com/~{username}",
        "check": "status_code",
        "valid": 200,
    },
    "PyPI": {
        "url": "https://pypi.org/user/{username}/",
        "check": "status_code",
        "valid": 200,
    },
    "Telegram": {
        "url": "https://t.me/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Patreon": {
        "url": "https://www.patreon.com/{username}",
        "check": "status_code",
        "valid": 200,
    },
    "Substack": {
        "url": "https://{username}.substack.com",
        "check": "status_code",
        "valid": 200,
    },
}


def _check_platform(platform: str, info: dict, username: str) -> tuple[str, str | None]:
    """Check if a username exists on a platform."""
    url = info["url"].format(username=username)
    try:
        resp = requests.get(
            url,
            timeout=get_timeout(),
            headers={"User-Agent": "HeavenlyEyes/1.0 OSINT Recon"},
            allow_redirects=True,
        )
        if info["check"] == "status_code":
            if resp.status_code == info["valid"]:
                return (platform, url)
        elif info["check"] == "text_absent":
            if info["invalid_text"] not in resp.text:
                return (platform, url)
    except requests.RequestException:
        pass
    return (platform, None)


def search_username(username: str, threads: int = 15) -> dict:
    """Search for a username across social media platforms."""
    print_section(f"Username Search: {username}")
    print_info(f"Checking {len(PLATFORMS)} platforms with {threads} threads...")

    found = {}
    table = create_table(
        f"Profiles for '{username}'",
        [("Platform", "cyan"), ("URL", "green"), ("Status", "white")],
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(_check_platform, platform, info, username): platform
            for platform, info in PLATFORMS.items()
        }
        for future in concurrent.futures.as_completed(futures):
            platform, url = future.result()
            if url:
                found[platform] = url
                table.add_row(platform, url, "[green]Found[/green]")

    if found:
        console.print(table)
        print_info(f"Found {len(found)} profile(s) across {len(PLATFORMS)} platforms")
    else:
        print_info("No profiles found")

    return found


def search_compounded(username: str) -> dict:
    """Search for related/compounded usernames."""
    print_section("Compounded Username Search")

    variations = [
        username,
        f"{username}1",
        f"{username}123",
        f"{username}_",
        f"_{username}",
        f"{username}official",
        f"real{username}",
        f"the{username}",
        f"{username}dev",
        f"{username}hq",
    ]

    print_info(f"Checking {len(variations)} username variations...")
    all_found = {}

    for variant in variations:
        if variant == username:
            continue
        # Quick check on key platforms only
        for platform in ["GitHub", "Twitter/X", "Instagram", "Reddit"]:
            if platform in PLATFORMS:
                _, url = _check_platform(platform, PLATFORMS[platform], variant)
                if url:
                    if variant not in all_found:
                        all_found[variant] = {}
                    all_found[variant][platform] = url

    if all_found:
        table = create_table(
            "Compounded Username Findings",
            [("Variation", "yellow"), ("Platform", "cyan"), ("URL", "green")],
        )
        for variant, platforms in all_found.items():
            for platform, url in platforms.items():
                table.add_row(variant, platform, url)
        console.print(table)
    else:
        print_info("No compounded username matches found")

    return all_found
