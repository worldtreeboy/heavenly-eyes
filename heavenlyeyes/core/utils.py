"""Shared utilities for HeavenlyEyes."""

import re
import socket
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from heavenlyeyes.core.config import get_timeout, get_user_agent

console = Console()


def banner():
    """Display the HeavenlyEyes banner."""
    art = r"""
    ██╗  ██╗███████╗ █████╗ ██╗   ██╗███████╗███╗   ██╗██╗  ██╗   ██╗
    ██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝████╗  ██║██║  ╚██╗ ██╔╝
    ███████║█████╗  ███████║██║   ██║█████╗  ██╔██╗ ██║██║   ╚████╔╝
    ██╔══██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║    ╚██╔╝
    ██║  ██║███████╗██║  ██║ ╚████╔╝ ███████╗██║ ╚████║███████╗██║
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝
    ███████╗██╗   ██╗███████╗███████╗
    ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
    █████╗   ╚████╔╝ █████╗  ███████╗
    ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
    ███████╗   ██║   ███████╗███████║
    ╚══════╝   ╚═╝   ╚══════╝╚══════╝
    """
    console.print(Panel(
        Text(art, style="bold cyan"),
        title="[bold white]HeavenlyEyes v1.0[/bold white]",
        subtitle="[dim]All-seeing OSINT Reconnaissance[/dim]",
        border_style="cyan",
    ))


def make_request(url: str, method: str = "GET", **kwargs) -> requests.Response | None:
    """Make an HTTP request with default headers and timeout."""
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", get_user_agent())
    timeout = kwargs.pop("timeout", get_timeout())
    try:
        resp = requests.request(method, url, headers=headers, timeout=timeout, **kwargs)
        return resp
    except requests.RequestException as e:
        console.print(f"[red]Request failed:[/red] {e}")
        return None


def resolve_host(hostname: str) -> str | None:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def is_valid_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def is_valid_ip(ip: str) -> bool:
    pattern = r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    return bool(re.match(pattern, ip))


def print_section(title: str):
    console.print(f"\n[bold cyan]{'━' * 60}[/bold cyan]")
    console.print(f"[bold white]  {title}[/bold white]")
    console.print(f"[bold cyan]{'━' * 60}[/bold cyan]\n")


def print_found(label: str, value: str):
    console.print(f"  [green]✔[/green] [bold]{label}:[/bold] {value}")


def print_not_found(label: str):
    console.print(f"  [red]✘[/red] [dim]{label}: Not found[/dim]")


def print_info(msg: str):
    console.print(f"  [blue]ℹ[/blue] {msg}")


def print_warning(msg: str):
    console.print(f"  [yellow]⚠[/yellow] {msg}")


def print_error(msg: str):
    console.print(f"  [red]✘[/red] {msg}")


def create_table(title: str, columns: list[tuple[str, str]]) -> Table:
    """Create a styled Rich table."""
    table = Table(title=title, border_style="cyan", header_style="bold white")
    for name, style in columns:
        table.add_column(name, style=style)
    return table
