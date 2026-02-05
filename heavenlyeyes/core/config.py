"""Configuration management for HeavenlyEyes."""

import os
import yaml
import webbrowser
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

CONFIG_DIR = Path.home() / ".heavenlyeyes"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
OUTPUT_DIR = Path.cwd() / "heyes_reports"

DEFAULT_CONFIG = {
    "api_keys": {
        "shodan": "",
        "haveibeenpwned": "",
        "hunter_io": "",
        "virustotal": "",
        "securitytrails": "",
        "censys_id": "",
        "censys_secret": "",
        "intelx": "",
        "dehashed": "",
        "dehashed_email": "",
        "leaklookup": "",
        "numverify": "",
        "wigle_name": "",
        "wigle_token": "",
    },
    "settings": {
        "timeout": 10,
        "max_threads": 20,
        "user_agent": "HeavenlyEyes/2.0 OSINT Recon Tool",
        "output_format": "json",
        "verbose": False,
    },
}

# ── API key registry: name → (env var, description, sign-up URL, features unlocked) ──

API_KEY_REGISTRY = {
    "shodan": {
        "env": "HEYES_SHODAN",
        "name": "Shodan",
        "url": "https://account.shodan.io/register",
        "features": "Origin IP via SSL/hostname/favicon, host enrichment, vuln scanning",
    },
    "haveibeenpwned": {
        "env": "HEYES_HAVEIBEENPWNED",
        "name": "Have I Been Pwned",
        "url": "https://haveibeenpwned.com/API/Key",
        "features": "Premium breach lookups for emails and domains",
    },
    "hunter_io": {
        "env": "HEYES_HUNTER_IO",
        "name": "Hunter.io",
        "url": "https://hunter.io/users/sign_up",
        "features": "Email pattern discovery and verification",
    },
    "virustotal": {
        "env": "HEYES_VIRUSTOTAL",
        "name": "VirusTotal",
        "url": "https://www.virustotal.com/gui/join-us",
        "features": "Domain reputation, URL scanning, malware checks",
    },
    "securitytrails": {
        "env": "HEYES_SECURITYTRAILS",
        "name": "SecurityTrails",
        "url": "https://securitytrails.com/app/signup",
        "features": "Historical DNS records, premium subdomain data",
    },
    "censys_id": {
        "env": "HEYES_CENSYS_ID",
        "name": "Censys (API ID)",
        "url": "https://search.censys.io/register",
        "features": "Internet-wide scan data, certificate search",
    },
    "censys_secret": {
        "env": "HEYES_CENSYS_SECRET",
        "name": "Censys (Secret)",
        "url": "https://search.censys.io/register",
        "features": "Internet-wide scan data, certificate search",
    },
    "intelx": {
        "env": "HEYES_INTELX",
        "name": "IntelligenceX",
        "url": "https://intelx.io/signup",
        "features": "Dark web search, paste monitoring, leaked data",
    },
    "dehashed": {
        "env": "HEYES_DEHASHED",
        "name": "Dehashed",
        "url": "https://dehashed.com/register",
        "features": "Breached credentials search, dark web monitoring",
    },
    "leaklookup": {
        "env": "HEYES_LEAKLOOKUP",
        "name": "LeakLookup",
        "url": "https://leak-lookup.com/account/register",
        "features": "Leaked database search by email/domain/username",
    },
    "numverify": {
        "env": "HEYES_NUMVERIFY",
        "name": "NumVerify",
        "url": "https://numverify.com/signup",
        "features": "Phone number validation, carrier lookup, line type",
    },
    "wigle_name": {
        "env": "HEYES_WIGLE_NAME",
        "name": "WiGLE (API Name)",
        "url": "https://wigle.net/account",
        "features": "WiFi geolocation, SSID search, BSSID lookup",
    },
    "wigle_token": {
        "env": "HEYES_WIGLE_TOKEN",
        "name": "WiGLE (API Token)",
        "url": "https://wigle.net/account",
        "features": "WiFi geolocation, SSID search, BSSID lookup",
    },
}

AI_KEY_REGISTRY = {
    "anthropic": {
        "env": "ANTHROPIC_API_KEY",
        "name": "Anthropic (Claude)",
        "url": "https://console.anthropic.com/",
        "features": "AI-powered intelligence synthesis with Claude",
    },
    "openai": {
        "env": "OPENAI_API_KEY",
        "name": "OpenAI (GPT)",
        "url": "https://platform.openai.com/signup",
        "features": "AI-powered intelligence synthesis with GPT",
    },
}


def ensure_config():
    """Create default config if it doesn't exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        with open(CONFIG_FILE, "w") as f:
            yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)
    return load_config()


def load_config() -> dict:
    """Load configuration from file."""
    if not CONFIG_FILE.exists():
        return DEFAULT_CONFIG.copy()
    with open(CONFIG_FILE) as f:
        config = yaml.safe_load(f) or {}
    merged = DEFAULT_CONFIG.copy()
    merged.update(config)
    return merged


def save_config(config: dict):
    """Save configuration to file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def get_api_key(service: str) -> str:
    """Get API key for a service, checking env vars first."""
    # Check registry for env var name
    reg = API_KEY_REGISTRY.get(service) or AI_KEY_REGISTRY.get(service)
    if reg:
        env_val = os.environ.get(reg["env"], "")
        if env_val:
            return env_val
    # Fallback generic env var
    env_key = f"HEYES_{service.upper()}"
    env_val = os.environ.get(env_key, "")
    if env_val:
        return env_val
    config = load_config()
    return config.get("api_keys", {}).get(service, "")


def get_timeout() -> int:
    config = load_config()
    return config.get("settings", {}).get("timeout", 10)


def get_user_agent() -> str:
    config = load_config()
    return config.get("settings", {}).get("user_agent", DEFAULT_CONFIG["settings"]["user_agent"])


# ════════════════════════════════════════════════════════════════════════
#  AUTO-CONFIG WIZARD
# ════════════════════════════════════════════════════════════════════════

def _mask_key(key: str) -> str:
    """Mask an API key for display (show first 4, last 4)."""
    if len(key) <= 10:
        return key[:2] + "•" * (len(key) - 2)
    return key[:4] + "•" * (len(key) - 8) + key[-4:]


def check_missing_keys() -> dict:
    """Return dict of missing keys grouped by priority."""
    missing = {"critical": [], "recommended": [], "optional": []}

    critical = ["shodan"]
    recommended = ["securitytrails", "haveibeenpwned", "virustotal"]
    optional = ["hunter_io", "censys_id", "censys_secret"]

    for key_name in critical:
        if not get_api_key(key_name):
            missing["critical"].append(key_name)
    for key_name in recommended:
        if not get_api_key(key_name):
            missing["recommended"].append(key_name)
    for key_name in optional:
        if not get_api_key(key_name):
            missing["optional"].append(key_name)

    # AI keys — check env directly
    has_ai = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"))
    config = load_config()
    ai_keys = config.get("api_keys", {})
    if not has_ai and not ai_keys.get("anthropic") and not ai_keys.get("openai"):
        missing["optional"].append("anthropic")

    return missing


def setup_wizard(console: Console | None = None):
    """Interactive setup wizard for API keys."""
    if console is None:
        console = Console()

    config = ensure_config()
    if "api_keys" not in config:
        config["api_keys"] = {}

    # ── Header ──
    console.print()
    console.print(Panel(
        "[bold cyan]HeavenlyEyes Setup Wizard[/bold cyan]\n\n"
        "[dim]Configure your API keys to unlock the full power of HeavenlyEyes.\n"
        "Keys are saved locally in ~/.heavenlyeyes/config.yaml[/dim]",
        border_style="cyan",
        padding=(1, 3),
    ))

    # ── Show current status ──
    table = Table(
        title="[bold]API Key Status[/bold]",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold white on #1a1a2e",
        padding=(0, 1),
    )
    table.add_column("Service", style="white", width=22)
    table.add_column("Status", width=14, justify="center")
    table.add_column("Features Unlocked", style="dim", ratio=1)

    all_keys = {**API_KEY_REGISTRY, **AI_KEY_REGISTRY}

    for key_name, info in all_keys.items():
        current = get_api_key(key_name)
        if not current and key_name in AI_KEY_REGISTRY:
            current = os.environ.get(info["env"], "")
            if not current:
                current = config.get("api_keys", {}).get(key_name, "")

        if current:
            status = f"[bold green]✔ {_mask_key(current)}[/bold green]"
        else:
            status = "[red]✘ Missing[/red]"

        table.add_row(info["name"], status, info["features"])

    console.print(table)
    console.print()

    # ── Count missing ──
    missing = check_missing_keys()
    total_missing = sum(len(v) for v in missing.values())

    if total_missing == 0:
        console.print("[bold green]All API keys are configured! You're all set.[/bold green]\n")
        return

    console.print(f"[yellow]{total_missing} key(s) not configured.[/yellow]")

    if missing["critical"]:
        console.print("[bold red]Critical:[/bold red] Shodan key is missing — origin IP discovery will be limited.")

    # ── Ask to configure ──
    console.print()
    if not Confirm.ask("[bold]Would you like to configure missing API keys now?[/bold]", default=True):
        console.print("[dim]Skipped. Run [bold]heavenlyeyes setup[/bold] anytime to configure.[/dim]\n")
        return

    # ── Walk through each missing key ──
    configured_count = 0

    for priority, key_list in [("critical", missing["critical"]),
                                ("recommended", missing["recommended"]),
                                ("optional", missing["optional"])]:
        for key_name in key_list:
            info = all_keys.get(key_name, API_KEY_REGISTRY.get(key_name))
            if not info:
                continue

            priority_badge = {
                "critical": "[bold red]CRITICAL[/bold red]",
                "recommended": "[yellow]RECOMMENDED[/yellow]",
                "optional": "[dim]OPTIONAL[/dim]",
            }[priority]

            console.print(f"\n  {priority_badge}  [bold]{info['name']}[/bold]")
            console.print(f"  [dim]{info['features']}[/dim]")

            # Offer to open sign-up page
            open_url = Confirm.ask(
                f"  Open sign-up page in browser? ({info['url']})",
                default=False,
            )
            if open_url:
                try:
                    webbrowser.open(info["url"])
                    console.print("  [green]Opened in browser.[/green]")
                except Exception:
                    console.print(f"  [dim]Visit: {info['url']}[/dim]")

            # Prompt for key
            key_val = Prompt.ask(
                f"  Enter {info['name']} API key (or press Enter to skip)",
                default="",
                show_default=False,
            )

            if key_val.strip():
                config["api_keys"][key_name] = key_val.strip()
                save_config(config)
                configured_count += 1
                console.print(f"  [green]✔ {info['name']} key saved![/green]")
            else:
                console.print(f"  [dim]Skipped. Set env var {info['env']} or run setup later.[/dim]")

    # ── Summary ──
    console.print()
    if configured_count > 0:
        console.print(Panel(
            f"[bold green]✔ {configured_count} key(s) configured and saved![/bold green]\n"
            f"[dim]Config: {CONFIG_FILE}[/dim]",
            border_style="green",
        ))
    else:
        console.print(Panel(
            "[yellow]No keys were configured.[/yellow]\n"
            "[dim]You can always set keys via environment variables:\n"
            "  export HEYES_SHODAN=your_key_here\n"
            f"  Or edit: {CONFIG_FILE}[/dim]",
            border_style="yellow",
        ))


def auto_check_keys(console: Console | None = None):
    """Quick check on startup — show one-liner if critical keys are missing."""
    if console is None:
        console = Console()

    missing = check_missing_keys()
    if missing["critical"]:
        names = [API_KEY_REGISTRY[k]["name"] for k in missing["critical"]]
        console.print(
            f"[yellow]⚠ Missing critical key(s): {', '.join(names)} — "
            f"run [bold]heavenlyeyes setup[/bold] to configure[/yellow]"
        )
