import sys
import click
from netfingerprinter.core.scanner import Scanner
from netfingerprinter.core import registry
from netfingerprinter.output.formatter import OutputFormatter


@click.group()
@click.version_option()
def cli():
    """Actively fingerprint network services via minimal protocol handshakes."""


@cli.command()
@click.argument("host")
@click.option("--port", "-p", type=int, required=True, help="Target port.")
@click.option(
    "--protocol",
    "-P",
    default=None,
    help="Force a specific protocol prober (ssh, http, https).",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["human", "json", "jsonl"]),
    default="human",
    show_default=True,
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=5.0,
    show_default=True,
    help="Connection timeout in seconds.",
)
@click.option("--no-color", is_flag=True, default=False)
def scan(host, port, protocol, output_format, timeout, no_color):
    """Fingerprint a single HOST:PORT."""
    result = Scanner(host, port, timeout=timeout, force_protocol=protocol).run()
    formatter = OutputFormatter(fmt=output_format, no_color=no_color)
    formatter.render(result)

    if result.error:
        if "refused" in (result.error or "").lower():
            sys.exit(1)
        elif "timeout" in (result.error or "").lower():
            sys.exit(2)
        elif "unknown protocol" in (result.error or "").lower():
            sys.exit(3)
        else:
            sys.exit(1)


@cli.command("list-protocols")
def list_protocols():
    """List all supported protocol probers."""
    # Ensure probers are imported so registry is populated
    import netfingerprinter.probers.ssh  # noqa: F401
    import netfingerprinter.probers.http  # noqa: F401

    probers = registry.all_probers()
    if not probers:
        click.echo("No protocols registered.")
        return
    click.echo(f"{'Protocol':<12} {'Default Ports'}")
    click.echo("-" * 30)
    for cls in probers:
        ports = ", ".join(str(p) for p in cls.DEFAULT_PORTS)
        click.echo(f"{cls.NAME:<12} {ports}")
