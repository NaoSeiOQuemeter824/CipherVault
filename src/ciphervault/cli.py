import sys
import logging
from pathlib import Path

import click
from cryptography.hazmat.primitives import serialization
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .crypto import KeyStore, SelfEncryptor
from .contacts import ContactsStore
from . import __version__

# =============================================================
# Módulo cli
# -------------------------------------------------------------
# Fornece:
#   - Grupo principal click com --debug e --version
#   - Modo interativo persistente (menu loop) para operações simples
#   - Comandos não interativos: encrypt, decrypt, keys, public-key, private-key
#   - Funções auxiliares para validação de caminhos e visualização de chaves
#
# Notas de Segurança:
#   - Expor a chave privada só deve ser feito conscientemente; acrescentado
#     painel de aviso e confirmação explícita.
#   - Chave pública é segura para divulgação / embutida no contentor.
# =============================================================

console = Console()


@click.group(invoke_without_command=True)
@click.option("--debug", is_flag=True, help="Ativar registos detalhados (debug)")
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx, debug: bool):
    """CipherVault Protótipo

    CLI mínima para cifrar/decifrar um único ficheiro para uso próprio.
    Suporta qualquer ficheiro (recomenda-se .zip/.rar para pastas, ou imagens).
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
    """Loop de menu interativo.

    Permite ao utilizador repetir operações sucessivamente sem relançar
    o processo. Cada escolha devolve ao menu após conclusão.
    """
    while True:
        console.clear()
        console.print(Panel("[bold cyan]CipherVault Protótipo[/bold cyan]\nCifrar/Decifrar para si (RSA-4096 + AES-256-GCM)", expand=False))
        console.print("\n[bold]Ações:[/bold]")
        console.print("  1) Cifrar ficheiro")
        console.print("  2) Decifrar ficheiro .cvault")
        console.print("  3) Ver chave [bold]pública[/bold]")
        console.print("  4) Contactos (adicionar/listar/apagar)")
        console.print("  5) Sair")
        choice = Prompt.ask("Escolha", choices=["1", "2", "3", "4", "5"], default="1")
        if choice == "1":
            _encrypt_flow()
            Prompt.ask("\nPrima Enter para voltar ao menu")
        elif choice == "2":
            _decrypt_flow()
            Prompt.ask("\nPrima Enter para voltar ao menu")
        elif choice == "3":
            _show_public_key()
            Prompt.ask("\nPrima Enter para voltar ao menu")
        elif choice == "4":
            _contacts_menu()
            # Ao sair dos Contactos, regressar imediatamente ao menu principal (sem pedir Enter)
        else:
            sys.exit(0)


def _show_public_key():
    """Mostra a chave pública em PEM (sem riscos de confidencialidade)."""
    ks = KeyStore(); ks.ensure_keys()
    pem = ks.get_public_pem().decode("utf-8", errors="ignore")
    panel = Panel(pem, title="Chave Pública (PEM)", expand=False)
    console.print(panel)


def _contacts_menu():
    store = ContactsStore()
    while True:
        console.clear()
        console.print(Panel("[bold cyan]Contactos[/bold cyan]", expand=False))
        console.print("  1) Adicionar contacto")
        console.print("  2) Listar contactos")
        console.print("  3) Apagar contacto")
        console.print("  4) Voltar")
        c = Prompt.ask("Escolha", choices=["1", "2", "3", "4"], default="2")
        if c == "1":
            _contact_add_flow(store)
            Prompt.ask("\nEnter para continuar")
        elif c == "2":
            _contact_list_flow(store)
            Prompt.ask("\nEnter para continuar")
        elif c == "3":
            _contact_delete_flow(store)
            Prompt.ask("\nEnter para continuar")
        else:
            break

def _contact_add_flow(store: ContactsStore):
    console.print("\n[bold]Adicionar novo contacto[/bold]")
    name = Prompt.ask("Nome do contacto")
    pem_path = Prompt.ask("Caminho para a chave pública (PEM)")
    p = Path(_clean_path(pem_path)).expanduser().resolve()
    if not p.exists() or not p.is_file():
        console.print("[red]Caminho inválido para PEM[/red]")
        return
    pem = p.read_text(encoding="utf-8", errors="ignore")
    try:
        store.add_contact(name, pem)
        console.print("[green]Contacto adicionado com sucesso[/green]")
    except Exception as e:
        console.print(f"[red]Falha ao adicionar:[/red] {e}")

def _contact_list_flow(store: ContactsStore):
    items = store.list_contacts()
    table = Table(title="Contactos", show_lines=True)
    table.add_column("Nome", style="cyan", no_wrap=True)
    table.add_column("Fingerprint (SHA-256)", style="white")
    table.add_column("Excerto PEM", style="white")
    for c in items:
        pem_lines = (c.get("public_pem") or "").splitlines()
        snippet = []
        if pem_lines:
            snippet.append(pem_lines[0])
        if len(pem_lines) > 1:
            snippet.append("…")
            snippet.append(pem_lines[-1])
        table.add_row(c.get("name", ""), c.get("fingerprint", ""), "\n".join(snippet))
    console.print(table)

def _contact_delete_flow(store: ContactsStore):
    name = Prompt.ask("Nome do contacto a apagar")
    ok = store.delete_contact(name)
    if ok:
        console.print("[yellow]Contacto removido[/yellow]")
    else:
        console.print("[red]Nenhum contacto com esse nome[/red]")


def _clean_path(path_str: str) -> str:
    """Normaliza caminho introduzido removendo aspas exteriores e espaços.

    Objetivo: tolerar colagem de caminhos provenientes do Explorador
    do Windows que frequentemente incluem aspas.
    """
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
        raise click.BadParameter(f"Caminho não encontrado: {p}")
    if p.is_dir():
        raise click.BadParameter("Selecionou uma pasta. Comprima-a para .zip/.rar e selecione o ficheiro resultante.")
    return p


def _encrypt_flow():
    """Fluxo interativo para cifrar um único ficheiro.

    Recolhe caminho, valida, executa cifragem híbrida e reporta resultado.
    """
    ks = KeyStore()
    ks.ensure_keys()
    se = SelfEncryptor(ks)

    console.print("\nIntroduza o [bold]caminho para o ficheiro[/bold] a cifrar (ex.: .zip/.rar ou imagem):")
    path_str = Prompt.ask("Caminho do ficheiro")
    try:
        in_path = _validate_input_path(path_str)
    except click.BadParameter as e:
        console.print(f"[red]Erro:[/red] {e}")
        return

    try:
        out_path = se.encrypt_file(in_path)
        console.print(f"\n[green]Sucesso![/green] Cifrado em: [bold]{out_path}[/bold]")
    except Exception as e:
        console.print(f"[red]Falha ao cifrar:[/red] {e}")


def _decrypt_flow():
    """Fluxo interativo para decifrar contentor .cvault.

    Valida extensão, decifra, verifica assinatura e escreve ficheiro original.
    """
    ks = KeyStore()
    ks.ensure_keys()
    se = SelfEncryptor(ks)

    console.print("\nIntroduza o [bold]caminho para o ficheiro .cvault[/bold] a decifrar:")
    path_str = Prompt.ask("Caminho do ficheiro .cvault")
    cleaned = _clean_path(path_str)
    p = Path(cleaned).expanduser().resolve()
    if not p.exists() or not p.is_file() or p.suffix != ".cvault":
        console.print("[red]Indique um caminho válido para um ficheiro .cvault[/red]")
        return

    try:
        out_path = se.decrypt_file(p)
        console.print(f"\n[green]Sucesso![/green] Decifrado em: [bold]{out_path}[/bold]")
    except Exception as e:
        console.print(f"[red]Falha ao decifrar:[/red] {e}")


@cli.command()
@click.argument("path", type=click.Path(path_type=Path))
def encrypt(path: Path):
    """Cifrar um ficheiro para si (modo não interativo)."""
    ks = KeyStore(); ks.ensure_keys(); se = SelfEncryptor(ks)
    p = path.expanduser().resolve()
    if not p.exists() or not p.is_file():
        raise click.ClickException(f"Caminho não encontrado ou não é um ficheiro: {p}")
    out = se.encrypt_file(p)
    console.print(f"[green]Cifrado:[/green] {out}")


@cli.command()
@click.argument("path", type=click.Path(path_type=Path))
def decrypt(path: Path):
    """Decifrar um ficheiro .cvault (modo não interativo)."""
    ks = KeyStore(); ks.ensure_keys(); se = SelfEncryptor(ks)
    p = path.expanduser().resolve()
    if not p.exists() or not p.is_file() or p.suffix != ".cvault":
        raise click.ClickException("Indique um caminho válido para um ficheiro .cvault")
    out = se.decrypt_file(p)
    console.print(f"[green]Decifrado:[/green] {out}")


@cli.command(name="keys")
def keys_info():
    """Mostrar onde as chaves estão guardadas e a sua impressão digital."""
    ks = KeyStore()
    ks.ensure_keys()

    table = Table(title="Informação do Cofre de Chaves", show_lines=True)
    table.add_column("Item", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")

    table.add_row("Diretoria base", str(ks.base_dir))
    table.add_row("Chave privada", str(ks.private_key_path))
    table.add_row("Chave pública", str(ks.public_key_path))

    try:
        fp = ks.get_fingerprint_hex()
    except Exception:
        fp = "<unavailable>"
    table.add_row("Impressão digital da chave pública (SHA-256)", fp)

    # Show a small snippet of the public key PEM to visually confirm
    try:
        pub_pem = ks.get_public_pem().decode("utf-8", errors="ignore").splitlines()
        snippet = []
        if pub_pem:
            snippet.append(pub_pem[0])
        if len(pub_pem) > 1:
            snippet.append("…")
            snippet.append(pub_pem[-1])
        table.add_row("Excerto do PEM público", "\n".join(snippet))
    except Exception:
        table.add_row("Excerto do PEM público", "<unavailable>")

    console.print(table)


@cli.command(name="public-key")
def public_key_cmd():
    """Imprimir chave pública em PEM."""
    ks = KeyStore(); ks.ensure_keys()
    console.print(ks.get_public_pem().decode("utf-8", errors="ignore"))

@cli.command(name="contacts-list")
def contacts_list_cmd():
    """Listar contactos guardados."""
    store = ContactsStore()
    _contact_list_flow(store)

@cli.command(name="contacts-add")
@click.option("--name", required=True, help="Nome do contacto")
@click.option("--pubkey", type=click.Path(path_type=Path), required=True, help="Caminho para PEM da chave pública")
def contacts_add_cmd(name: str, pubkey: Path):
    """Adicionar um contacto (nome + chave pública PEM)."""
    store = ContactsStore()
    p = pubkey.expanduser().resolve()
    if not p.exists() or not p.is_file():
        raise click.ClickException("Caminho inválido para PEM")
    pem = p.read_text(encoding="utf-8", errors="ignore")
    store.add_contact(name, pem)
    console.print("[green]Contacto adicionado[/green]")

@cli.command(name="contacts-delete")
@click.option("--name", required=True, help="Nome do contacto a apagar")
def contacts_delete_cmd(name: str):
    """Apagar um contacto pelo nome."""
    store = ContactsStore()
    if not store.delete_contact(name):
        raise click.ClickException("Contacto não encontrado")
    console.print("[yellow]Contacto removido[/yellow]")
