import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from netfingerprinter.core.result import FingerprintResult, Confidence

_CONFIDENCE_COLOR = {
    Confidence.CONFIRMED: "green",
    Confidence.HIGH: "yellow",
    Confidence.LOW: "dim",
}


class OutputFormatter:
    def __init__(self, fmt: str = "human", no_color: bool = False):
        self.fmt = fmt
        self.console = Console(highlight=False, no_color=no_color)

    def render(self, result: FingerprintResult) -> None:
        if self.fmt == "json":
            print(json.dumps(result.to_dict(), indent=2))
        elif self.fmt == "jsonl":
            print(json.dumps(result.to_dict()))
        else:
            self._render_human(result)

    def _render_human(self, result: FingerprintResult) -> None:
        if result.error:
            self.console.print(
                Panel(
                    f"[red]Error:[/red] {result.error}",
                    title=f"{result.host}:{result.port}",
                    border_style="red",
                )
            )
            return

        color = _CONFIDENCE_COLOR.get(result.confidence, "white")
        identity = f"{result.software or '?'}"
        if result.version:
            identity += f"  [dim]{result.version}[/dim]"

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("Key", style="bold cyan", no_wrap=True)
        table.add_column("Value")

        table.add_row("Protocol", result.protocol.upper())
        table.add_row("Software", identity)
        table.add_row("Confidence", f"[{color}]{result.confidence.value}[/{color}]")

        if result.banner:
            table.add_row("Banner", f"[dim]{result.banner.strip()}[/dim]")

        if result.http_status is not None:
            table.add_row("HTTP Status", str(result.http_status))

        if result.tls_version:
            table.add_row("TLS", f"{result.tls_version}  {result.tls_cipher or ''}")

        if result.ssh_kex_algorithms:
            table.add_row("KEX", ", ".join(result.ssh_kex_algorithms))
        if result.ssh_ciphers:
            table.add_row("Ciphers", ", ".join(result.ssh_ciphers))
        if result.ssh_macs:
            table.add_row("MACs", ", ".join(result.ssh_macs))
        if result.ssh_host_key_algorithms:
            table.add_row("Host Keys", ", ".join(result.ssh_host_key_algorithms))

        self.console.print(
            Panel(
                table,
                title=f"[bold]{result.host}:{result.port}[/bold]",
                border_style="cyan",
            )
        )
