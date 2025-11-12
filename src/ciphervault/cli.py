import sys
import logging
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .crypto import KeyStore, SelfEncryptor
from . import __version__

console = Console()


@click.group(invoke_without_command=True)
@click.option("--debug", is_flag=True, help="Enable verbose debug logging")
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx, debug: bool):
    """CipherVault Prototype

    Minimal CLI to encrypt/decrypt a single file for yourself.
    Supported inputs: any regular file (recommend .zip/.rar for folders, or images).
    """
    # Configure logging once
    log_level = logging.DEBUG if debug else logging.INFO
    logger = logging.getLogger()
    if not logger.handlers:
        logging.basicConfig(level=log_level, format="[%(levelname)s] %(message)s")
    else:
        logger.setLevel(log_level)

    if ctx.invoked_subcommand is None:
        _interactive()


def _interactive():
    console.print(Panel("[bold cyan]CipherVault Prototype[/bold cyan]\nEncrypt/Decrypt for self (RSA-4096 + AES-256-GCM)", expand=False))
    console.print("\n[bold]Actions:[/bold] 1) Encrypt a file   2) Decrypt a .cvault file   3) Exit\n")
    choice = Prompt.ask("Choose", choices=["1", "2", "3"], default="1")
    if choice == "1":
        _encrypt_flow()
    elif choice == "2":
        _decrypt_flow()
    else:
        sys.exit(0)


def _clean_path(path_str: str) -> str:
    """Normalize a user-entered path: trim whitespace and surrounding quotes."""
    if path_str is None:
        return ""
    s = path_str.strip()
    # Strip matching quotes if present
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()
    return s


def _validate_input_path(path_str: str) -> Path:
    cleaned = _clean_path(path_str)
    p = Path(cleaned).expanduser().resolve()
    if not p.exists():
        raise click.BadParameter(f"Path not found: {p}")
    if p.is_dir():
        raise click.BadParameter("You selected a folder. Please compress it to .zip/.rar first, then select that file.")
    return p


def _encrypt_flow():
    ks = KeyStore()
    ks.ensure_keys()
    se = SelfEncryptor(ks)

    console.print("\nEnter the [bold]path to a file[/bold] to encrypt (e.g., a .zip/.rar or image):")
    path_str = Prompt.ask("File path")
    try:
        in_path = _validate_input_path(path_str)
    except click.BadParameter as e:
        console.print(f"[red]Error:[/red] {e}")
        return

    try:
        out_path = se.encrypt_file(in_path)
        console.print(f"\n[green]Success![/green] Encrypted to: [bold]{out_path}[/bold]")
    except Exception as e:
        console.print(f"[red]Encryption failed:[/red] {e}")


def _decrypt_flow():
    ks = KeyStore()
    ks.ensure_keys()
    se = SelfEncryptor(ks)

    console.print("\nEnter the [bold]path to a .cvault file[/bold] to decrypt:")
    path_str = Prompt.ask("Vault file path")
    cleaned = _clean_path(path_str)
    p = Path(cleaned).expanduser().resolve()
    if not p.exists() or not p.is_file() or p.suffix != ".cvault":
        console.print("[red]Please provide a valid .cvault file path[/red]")
        return

    try:
        out_path = se.decrypt_file(p)
        console.print(f"\n[green]Success![/green] Decrypted to: [bold]{out_path}[/bold]")
    except Exception as e:
        console.print(f"[red]Decryption failed:[/red] {e}")


@cli.command()
@click.argument("path", type=click.Path(path_type=Path))
def encrypt(path: Path):
    """Encrypt a file for yourself (non-interactive)."""
    ks = KeyStore(); ks.ensure_keys(); se = SelfEncryptor(ks)
    p = path.expanduser().resolve()
    if not p.exists() or not p.is_file():
        raise click.ClickException(f"Path not found or not a file: {p}")
    out = se.encrypt_file(p)
    console.print(f"[green]Encrypted:[/green] {out}")


@cli.command()
@click.argument("path", type=click.Path(path_type=Path))
def decrypt(path: Path):
    """Decrypt a .cvault file (non-interactive)."""
    ks = KeyStore(); ks.ensure_keys(); se = SelfEncryptor(ks)
    p = path.expanduser().resolve()
    if not p.exists() or not p.is_file() or p.suffix != ".cvault":
        raise click.ClickException("Please provide a valid .cvault file path")
    out = se.decrypt_file(p)
    console.print(f"[green]Decrypted:[/green] {out}")


@cli.command(name="keys")
def keys_info():
    """Show where your keys are stored and basic fingerprints."""
    ks = KeyStore()
    ks.ensure_keys()

    table = Table(title="Key Store Info", show_lines=True)
    table.add_column("Item", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    table.add_row("Base dir", str(ks.base_dir))
    table.add_row("Private key", str(ks.private_key_path))
    table.add_row("Public key", str(ks.public_key_path))

    try:
        fp = ks.get_fingerprint_hex()
    except Exception:
        fp = "<unavailable>"
    table.add_row("Public key fingerprint (SHA-256)", fp)

    # Show a small snippet of the public key PEM to visually confirm
    try:
        pub_pem = ks.get_public_pem().decode("utf-8", errors="ignore").splitlines()
        snippet = []
        if pub_pem:
            snippet.append(pub_pem[0])
        if len(pub_pem) > 1:
            snippet.append("…")
            snippet.append(pub_pem[-1])
        table.add_row("Public PEM snippet", "\n".join(snippet))
    except Exception:
        table.add_row("Public PEM snippet", "<unavailable>")

    console.print(table)
