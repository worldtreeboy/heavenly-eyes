"""Configuration management for HeavenlyEyes."""

import os
import yaml
from pathlib import Path

CONFIG_DIR = Path.home() / ".heavenlyeyes"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
OUTPUT_DIR = Path.cwd() / "heyes_reports"

DEFAULT_CONFIG = {
    "api_keys": {
        "shodan": "",
        "haveibeenpwned": "",
        "hunter_io": "",
        "virustotal": "",
    },
    "settings": {
        "timeout": 10,
        "max_threads": 20,
        "user_agent": "HeavenlyEyes/1.0 OSINT Recon Tool",
        "output_format": "json",
        "verbose": False,
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


def get_api_key(service: str) -> str:
    """Get API key for a service, checking env vars first."""
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
