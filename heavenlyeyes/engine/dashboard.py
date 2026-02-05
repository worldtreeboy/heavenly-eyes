"""Rich terminal dashboard — live progress, tables, and status panels."""

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box

from heavenlyeyes.engine.confidence import Finding

console = Console()

BANNER = r"""[bold cyan]
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
    ╚══════╝   ╚═╝   ╚══════╝╚══════╝[/bold cyan]"""


def print_banner():
    console.print(BANNER)
    console.print(
        Panel(
            "[bold white]All-seeing OSINT Reconnaissance[/bold white]\n"
            "[dim]v2.0 — Recursive Pivot Engine[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


def print_disclaimer():
    console.print(
        Panel(
            "[bold yellow]⚠  LEGAL DISCLAIMER[/bold yellow]\n\n"
            "[white]This tool is designed for [bold]authorized security testing[/bold], "
            "[bold]OSINT research[/bold], [bold]CTF competitions[/bold], "
            "and [bold]educational purposes[/bold] only.\n\n"
            "You must have [bold]explicit authorization[/bold] before conducting "
            "reconnaissance on any target. Unauthorized use may violate local, "
            "state, and federal laws.\n\n"
            "The developers assume [bold red]NO LIABILITY[/bold red] for misuse of this tool.[/white]",
            title="[bold red]DISCLAIMER[/bold red]",
            border_style="red",
            padding=(1, 3),
        )
    )


def print_target_info(input_type: str, target: str, depth: int):
    table = Table(box=box.HEAVY_EDGE, border_style="cyan", show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold cyan", width=16)
    table.add_column("Value", style="bold white")
    table.add_row("Target", target)
    table.add_row("Input Type", input_type.upper())
    table.add_row("Pivot Depth", str(depth))
    table.add_row("Mode", "Recursive Pivot + Stealth")
    console.print(Panel(table, title="[bold]Target Configuration[/bold]", border_style="cyan"))


def print_phase(name: str, icon: str = "➤"):
    console.print(f"\n[bold cyan]{icon} {name}[/bold cyan]")
    console.print(f"[cyan]{'─' * 60}[/cyan]")


def print_finding(f: Finding):
    conf_bar = _confidence_bar(f.confidence)
    console.print(
        f"  [{f.confidence_color}]●[/{f.confidence_color}] "
        f"[bold]{f.label}[/bold]: {f.value}  "
        f"{conf_bar} [dim]{f.confidence}%[/dim]  "
        f"[dim italic]via {f.source}[/dim italic]"
    )


def _confidence_bar(score: int) -> str:
    filled = score // 10
    empty = 10 - filled
    if score >= 75:
        color = "green"
    elif score >= 55:
        color = "yellow"
    else:
        color = "red"
    return f"[{color}]{'█' * filled}{'░' * empty}[/{color}]"


def print_pivot_branch(depth: int, pivot_type: str, pivot_value: str):
    indent = "  " * depth
    connector = "├──" if depth > 0 else "┌──"
    console.print(
        f"[dim]{indent}{connector}[/dim] "
        f"[bold magenta]PIVOT[/bold magenta] "
        f"[cyan]{pivot_type}[/cyan] → [white]{pivot_value}[/white]"
    )


def build_findings_table(findings: list[Finding], title: str = "Findings") -> Table:
    table = Table(
        title=f"[bold]{title}[/bold]",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold white on #1a1a2e",
        row_styles=["", "dim"],
        padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Category", style="cyan", width=14)
    table.add_column("Finding", style="bold white", max_width=40)
    table.add_column("Value", style="white", max_width=50)
    table.add_column("Confidence", justify="center", width=16)
    table.add_column("Source", style="dim", max_width=25)

    sorted_findings = sorted(findings, key=lambda f: f.confidence, reverse=True)
    for i, f in enumerate(sorted_findings, 1):
        conf_bar = _confidence_bar(f.confidence)
        table.add_row(
            str(i),
            f.category,
            f.label,
            f.value if len(f.value) <= 50 else f.value[:47] + "...",
            f"{conf_bar} {f.confidence}%",
            f.source,
        )

    return table


def build_summary_panel(
    target: str,
    total_findings: int,
    pivots_explored: int,
    categories: dict[str, int],
    avg_confidence: float,
    risk_score: int,
) -> Panel:
    risk_color = "green" if risk_score < 30 else "yellow" if risk_score < 60 else "red"
    risk_label = "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 60 else "HIGH" if risk_score < 80 else "CRITICAL"

    # Stats column
    stats = Table(box=None, show_header=False, padding=(0, 1))
    stats.add_column("K", style="cyan")
    stats.add_column("V", style="bold white")
    stats.add_row("Target", target)
    stats.add_row("Total Findings", str(total_findings))
    stats.add_row("Pivots Explored", str(pivots_explored))
    stats.add_row("Avg Confidence", f"{avg_confidence:.0f}%")
    stats.add_row("Risk Score", f"[{risk_color}]{risk_score}/100 — {risk_label}[/{risk_color}]")

    # Categories breakdown
    cat_table = Table(box=None, show_header=False, padding=(0, 1))
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Count", style="bold white", justify="right")
    for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
        cat_table.add_row(cat, str(count))

    content = Columns([stats, cat_table], padding=(0, 4))

    return Panel(
        content,
        title=f"[bold]Digital Footprint Summary — {target}[/bold]",
        subtitle=f"[dim]Risk: [{risk_color}]{risk_label}[/{risk_color}][/dim]",
        border_style=risk_color,
        padding=(1, 2),
    )


def create_progress() -> Progress:
    return Progress(
        SpinnerColumn("dots", style="cyan"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(bar_width=30, complete_style="cyan", finished_style="green"),
        TextColumn("[dim]{task.fields[status]}[/dim]"),
        console=console,
    )
