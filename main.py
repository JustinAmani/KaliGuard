#!/usr/bin/env python3
"""
KaliGuard AI - Defensive Cybersecurity Agent
Main CLI entry point using Click and Rich.

LEGAL: Authorized use only on networks/systems you own or have explicit written permission to test.
"""

import os
import sys
import yaml
import click
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box
from rich.live import Live
from rich.spinner import Spinner

console = Console()

BANNER = """
 ██╗  ██╗ █████╗ ██╗      ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ██║ ██╔╝██╔══██╗██║      ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 █████╔╝ ███████║██║      ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██╔═██╗ ██╔══██║██║      ██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ██║  ██╗██║  ██║███████╗ ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝

           ╔═══════════════════════════════════════════╗
           ║   AI-Powered Defensive Security Agent     ║
           ║   v1.0.0  |  Authorized Use Only          ║
           ╚═══════════════════════════════════════════╝
"""


def load_config(config_path="config.yaml"):
    """Load configuration from YAML file."""
    if not os.path.exists(config_path):
        console.print(f"[red]Config file not found: {config_path}[/red]")
        console.print("[yellow]Run install.sh first or copy config.yaml.example to config.yaml[/yellow]")
        sys.exit(1)
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def show_banner():
    """Display the KaliGuard banner."""
    console.print(Text(BANNER, style="bold cyan"))
    console.print(
        Panel(
            "[bold yellow]WARNING:[/bold yellow] For authorized use only. "
            "Ensure you have explicit permission before scanning any target.\n"
            "[dim]See LEGAL_DISCLAIMER.md for full terms of use.[/dim]",
            border_style="red",
            title="[bold red]LEGAL NOTICE[/bold red]",
        )
    )
    console.print()


def acknowledge_legal(config):
    """Prompt user to acknowledge legal disclaimer."""
    if config.get("security", {}).get("require_authorization_acknowledgment", True):
        console.print(
            Panel(
                "By proceeding, you confirm that:\n"
                "  [green]1.[/green] You own the target network/system, OR have explicit written authorization\n"
                "  [green]2.[/green] You are operating within your organization's authorized IP ranges\n"
                "  [green]3.[/green] You understand and accept full legal responsibility for your actions",
                title="[bold yellow]Authorization Acknowledgment Required[/bold yellow]",
                border_style="yellow",
            )
        )
        if not Confirm.ask("[bold yellow]Do you confirm you are authorized to proceed?[/bold yellow]"):
            console.print("[red]Authorization not confirmed. Exiting.[/red]")
            sys.exit(0)
        console.print()


@click.group()
@click.option("--config", default="config.yaml", help="Path to config file", show_default=True)
@click.option("--dry-run", is_flag=True, default=False, help="Simulate actions without executing real commands")
@click.option("--no-banner", is_flag=True, default=False, help="Suppress banner display")
@click.pass_context
def cli(ctx, config, dry_run, no_banner):
    """
    KaliGuard AI - Defensive Cybersecurity Agent

    An AI-powered penetration testing assistant using Claude AI and Kali Linux tools.
    For authorized use only on networks and systems you own or have explicit permission to test.
    """
    ctx.ensure_object(dict)
    if not no_banner:
        show_banner()
    cfg = load_config(config)
    if dry_run:
        cfg["security"]["dry_run"] = True
        console.print("[bold yellow][DRY RUN MODE][/bold yellow] No real commands will be executed.\n")
    ctx.obj["config"] = cfg
    ctx.obj["dry_run"] = dry_run or cfg.get("security", {}).get("dry_run", False)
    ctx.obj["config_path"] = config


@cli.command()
@click.argument("target")
@click.option("--ports", default="1-1000", help="Port range to scan", show_default=True)
@click.option("--scan-type", default="SYN", type=click.Choice(["SYN", "TCP", "UDP", "ACK", "FIN", "XMAS", "NULL"]), help="Nmap scan type")
@click.option("--full", is_flag=True, default=False, help="Run full port scan (1-65535)")
@click.option("--session-id", default=None, help="Session ID to associate findings with")
@click.pass_context
def scan(ctx, target, ports, scan_type, full, session_id):
    """
    Launch a network scan against TARGET.

    TARGET can be an IP address, hostname, or CIDR range (e.g. 192.168.1.0/24).
    Only targets within allowed networks will be scanned.

    Examples:

      kaliguard scan 192.168.1.1

      kaliguard scan 192.168.1.0/24 --ports 1-65535

      kaliguard scan 10.0.0.1 --scan-type UDP
    """
    cfg = ctx.obj["config"]
    dry_run = ctx.obj["dry_run"]
    acknowledge_legal(cfg)

    if full:
        ports = "1-65535"

    if not session_id:
        session_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    console.print(f"[bold cyan]Starting network scan[/bold cyan]")
    console.print(f"  Target    : [green]{target}[/green]")
    console.print(f"  Ports     : [green]{ports}[/green]")
    console.print(f"  Scan type : [green]{scan_type}[/green]")
    console.print(f"  Session   : [dim]{session_id}[/dim]")
    console.print()

    try:
        from agent import KaliGuardAgent
        agent = KaliGuardAgent(config=cfg, dry_run=dry_run)

        if not agent._is_safe_target(target):
            console.print(f"[bold red]ERROR:[/bold red] Target {target} is not in allowed networks.")
            console.print(f"[yellow]Allowed networks: {cfg['security']['allowed_networks']}[/yellow]")
            sys.exit(1)

        prompt = (
            f"Perform a network scan on target {target}. "
            f"Use port range {ports} with scan type {scan_type}. "
            f"Analyze the results and provide a security assessment with findings and recommendations. "
            f"Session ID: {session_id}"
        )
        result = agent.chat(prompt, session_id=session_id)
        console.print(Panel(result, title="[bold green]Scan Results[/bold green]", border_style="green"))

    except ImportError as e:
        console.print(f"[red]Failed to import agent module: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Scan error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("target")
@click.option("--depth", default="standard", type=click.Choice(["quick", "standard", "deep", "full"]), help="Audit depth")
@click.option("--session-id", default=None, help="Session ID for this audit")
@click.option("--output-format", default="pdf", type=click.Choice(["pdf", "html", "json"]), help="Report output format")
@click.pass_context
def audit(ctx, target, depth, session_id, output_format):
    """
    Run a full network security audit against TARGET.

    Performs comprehensive scanning including network discovery, vulnerability
    scanning, service enumeration, and web application testing.

    Examples:

      kaliguard audit 192.168.1.0/24

      kaliguard audit 192.168.1.1 --depth deep --output-format html
    """
    cfg = ctx.obj["config"]
    dry_run = ctx.obj["dry_run"]
    acknowledge_legal(cfg)

    if not session_id:
        session_id = f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    depth_steps = {
        "quick": ["nmap_scan", "whois_lookup"],
        "standard": ["nmap_scan", "nikto_scan", "gobuster_scan", "searchsploit_search"],
        "deep": ["nmap_scan", "nikto_scan", "openvas_scan", "gobuster_scan", "searchsploit_search", "enum4linux_scan"],
        "full": ["nmap_scan", "nikto_scan", "openvas_scan", "gobuster_scan", "sqlmap_scan", "searchsploit_search", "enum4linux_scan", "wpscan"],
    }

    steps = depth_steps.get(depth, depth_steps["standard"])

    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Depth:[/bold] {depth}\n"
        f"[bold]Steps:[/bold] {', '.join(steps)}\n"
        f"[bold]Session:[/bold] {session_id}\n"
        f"[bold]Report:[/bold] {output_format.upper()}",
        title="[bold cyan]Full Network Audit[/bold cyan]",
        border_style="cyan",
    ))

    try:
        from agent import KaliGuardAgent
        agent = KaliGuardAgent(config=cfg, dry_run=dry_run)

        if not agent._is_safe_target(target):
            console.print(f"[bold red]ERROR:[/bold red] Target {target} is not in allowed networks.")
            sys.exit(1)

        prompt = (
            f"Perform a full {depth} security audit on {target}. "
            f"Run the following tools in sequence: {', '.join(steps)}. "
            f"For each result, analyze findings and identify vulnerabilities. "
            f"Save all findings to the database. "
            f"At the end, generate a comprehensive security report in {output_format} format. "
            f"Session ID: {session_id}"
        )
        result = agent.chat(prompt, session_id=session_id)
        console.print(Panel(result, title="[bold green]Audit Complete[/bold green]", border_style="green"))

    except Exception as e:
        console.print(f"[red]Audit error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option("--memory-file", default=None, help="Path to memory dump file for analysis")
@click.option("--target-file", default=None, help="Path to suspicious file for analysis")
@click.option("--check-rootkits", is_flag=True, default=False, help="Run rootkit detection tools")
@click.option("--session-id", default=None, help="Session ID for this forensic analysis")
@click.pass_context
def forensics(ctx, memory_file, target_file, check_rootkits, session_id):
    """
    Perform forensic analysis on memory dumps, files, or the running system.

    Runs volatility, yara, binwalk, chkrootkit, rkhunter, and other forensic tools.

    Examples:

      kaliguard forensics --check-rootkits

      kaliguard forensics --memory-file /tmp/memory.dmp

      kaliguard forensics --target-file /tmp/suspicious.exe
    """
    cfg = ctx.obj["config"]
    dry_run = ctx.obj["dry_run"]

    if not session_id:
        session_id = f"forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    console.print(Panel(
        "[bold cyan]Forensic Analysis Mode[/bold cyan]\n"
        "Analyzing system for indicators of compromise...",
        border_style="cyan",
    ))

    try:
        from agent import KaliGuardAgent
        agent = KaliGuardAgent(config=cfg, dry_run=dry_run)

        parts = []
        if memory_file:
            parts.append(f"Analyze the memory dump at {memory_file} using volatility. Run pslist, pstree, netscan, and malfind plugins.")
        if target_file:
            parts.append(f"Analyze the suspicious file at {target_file} using binwalk, strings, yara, and file command.")
        if check_rootkits:
            parts.append("Run chkrootkit and rkhunter to check for rootkits on this system.")
        if not parts:
            parts.append("Perform a comprehensive forensic analysis of this system: check for rootkits, analyze running processes, check for suspicious files, and look for indicators of compromise.")

        prompt = " ".join(parts) + f" Session ID: {session_id}. Save all findings to the database."
        result = agent.chat(prompt, session_id=session_id)
        console.print(Panel(result, title="[bold green]Forensic Analysis Results[/bold green]", border_style="green"))

    except Exception as e:
        console.print(f"[red]Forensics error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option("--interface", default="eth0", help="Network interface to monitor", show_default=True)
@click.option("--duration", default=60, help="Monitoring duration in seconds", show_default=True)
@click.option("--filter", "filter_expr", default="", help="BPF filter expression (e.g. 'tcp port 80')")
@click.option("--ids", is_flag=True, default=False, help="Enable IDS mode with Snort/Suricata")
@click.option("--session-id", default=None, help="Session ID for this monitoring session")
@click.pass_context
def monitor(ctx, interface, duration, filter_expr, ids, session_id):
    """
    Monitor network traffic on the specified interface.

    Captures packets and analyzes for suspicious activity. Can enable IDS mode
    with Snort or Suricata for signature-based detection.

    Examples:

      kaliguard monitor --interface eth0 --duration 120

      kaliguard monitor --interface wlan0 --filter "tcp port 443" --ids
    """
    cfg = ctx.obj["config"]
    dry_run = ctx.obj["dry_run"]

    if not session_id:
        session_id = f"monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    console.print(Panel(
        f"[bold]Interface:[/bold] {interface}\n"
        f"[bold]Duration:[/bold] {duration}s\n"
        f"[bold]Filter:[/bold] {filter_expr or 'None'}\n"
        f"[bold]IDS Mode:[/bold] {'Enabled (Snort/Suricata)' if ids else 'Disabled'}",
        title="[bold cyan]Network Monitor[/bold cyan]",
        border_style="cyan",
    ))

    try:
        from agent import KaliGuardAgent
        agent = KaliGuardAgent(config=cfg, dry_run=dry_run)

        ids_part = " Also run Snort and Suricata IDS for signature-based threat detection." if ids else ""
        prompt = (
            f"Monitor network traffic on interface {interface} for {duration} seconds."
            f"{' Apply BPF filter: ' + filter_expr if filter_expr else ''}"
            f"{ids_part}"
            f" Analyze captured traffic for suspicious patterns, unusual connections, and security anomalies."
            f" Session ID: {session_id}"
        )
        result = agent.chat(prompt, session_id=session_id)
        console.print(Panel(result, title="[bold green]Monitoring Results[/bold green]", border_style="green"))

    except Exception as e:
        console.print(f"[red]Monitor error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option("--session-id", required=True, help="Session ID to generate report for")
@click.option("--format", "output_format", default="pdf", type=click.Choice(["pdf", "html", "json"]), help="Report format")
@click.option("--output-dir", default="reports/", help="Directory to save report", show_default=True)
@click.option("--title", default=None, help="Custom report title")
@click.pass_context
def report(ctx, session_id, output_format, output_dir, title):
    """
    Generate a security report for a completed audit/scan session.

    Compiles all findings from the session into a formatted report with
    executive summary, technical details, and remediation recommendations.

    Examples:

      kaliguard report --session-id audit_20260409_120000

      kaliguard report --session-id scan_20260409_120000 --format html
    """
    cfg = ctx.obj["config"]
    dry_run = ctx.obj["dry_run"]

    report_title = title or f"KaliGuard Security Report - {session_id}"

    console.print(Panel(
        f"[bold]Session ID:[/bold] {session_id}\n"
        f"[bold]Format:[/bold] {output_format.upper()}\n"
        f"[bold]Output:[/bold] {output_dir}\n"
        f"[bold]Title:[/bold] {report_title}",
        title="[bold cyan]Report Generator[/bold cyan]",
        border_style="cyan",
    ))

    try:
        from agent import KaliGuardAgent
        agent = KaliGuardAgent(config=cfg, dry_run=dry_run)

        prompt = (
            f"Generate a comprehensive security report for session {session_id}. "
            f"First retrieve all findings from the database using get_session_findings. "
            f"Then generate a {output_format} report with title '{report_title}' in {output_dir}. "
            f"Include executive summary, risk ratings, technical details, and remediation recommendations."
        )
        result = agent.chat(prompt, session_id=session_id)
        console.print(Panel(result, title="[bold green]Report Generated[/bold green]", border_style="green"))

    except Exception as e:
        console.print(f"[red]Report error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option("--session-id", default=None, help="Session ID (auto-generated if not provided)")
@click.pass_context
def chat(ctx, session_id):
    """
    Enter interactive AI chat mode with KaliGuard AI.

    This is the main mode for interacting with the AI agent. You can ask it to
    perform scans, analyze results, generate reports, and get security advice.

    The AI has access to all KaliGuard tools and will guide you through
    security assessments conversationally.

    Examples:

      kaliguard chat

      kaliguard chat --session-id my_audit_session
    """
    cfg = ctx.obj["config"]
    dry_run = ctx.obj["dry_run"]
    acknowledge_legal(cfg)

    if not session_id:
        session_id = f"chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    console.print(Panel(
        f"[bold green]KaliGuard AI Chat Mode[/bold green]\n\n"
        f"Session: [dim]{session_id}[/dim]\n\n"
        f"I am your AI-powered defensive security assistant. I can help you:\n"
        f"  • [cyan]Scan networks[/cyan] - nmap, masscan, arp-scan\n"
        f"  • [cyan]Find vulnerabilities[/cyan] - nikto, openvas, searchsploit\n"
        f"  • [cyan]Analyze forensics[/cyan] - volatility, yara, binwalk\n"
        f"  • [cyan]Monitor traffic[/cyan] - tcpdump, snort, suricata\n"
        f"  • [cyan]Test web apps[/cyan] - sqlmap, gobuster, burpsuite\n"
        f"  • [cyan]Crack passwords[/cyan] - hashcat, john, hydra\n"
        f"  • [cyan]Generate reports[/cyan] - PDF/HTML security reports\n\n"
        f"Type [bold]'exit'[/bold] or [bold]'quit'[/bold] to leave chat mode.\n"
        f"Type [bold]'help'[/bold] for example commands.",
        border_style="green",
    ))

    try:
        from agent import KaliGuardAgent
        agent = KaliGuardAgent(config=cfg, dry_run=dry_run)
    except Exception as e:
        console.print(f"[red]Failed to initialize agent: {e}[/red]")
        console.print("[yellow]Make sure ANTHROPIC_API_KEY is set in your environment.[/yellow]")
        sys.exit(1)

    help_text = (
        "\n[bold cyan]Example commands:[/bold cyan]\n"
        "  • Scan 192.168.1.0/24 for open ports\n"
        "  • Run a vulnerability scan on 192.168.1.100\n"
        "  • Check for rootkits on this system\n"
        "  • Capture traffic on eth0 for 30 seconds\n"
        "  • Test web app at http://192.168.1.100 for SQL injection\n"
        "  • Analyze the binary at /tmp/suspicious\n"
        "  • Generate a report for session " + session_id + "\n"
    )

    history = []

    while True:
        try:
            user_input = Prompt.ask("\n[bold green]You[/bold green]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Exiting chat mode. Goodbye![/yellow]")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit", "q", "bye"):
            console.print("[yellow]Exiting chat mode. Goodbye![/yellow]")
            break

        if user_input.lower() == "help":
            console.print(help_text)
            continue

        if user_input.lower().startswith("history"):
            if history:
                table = Table(title="Chat History", box=box.ROUNDED)
                table.add_column("Role", style="cyan", width=10)
                table.add_column("Message", style="white")
                for entry in history[-10:]:
                    table.add_row(entry["role"].capitalize(), entry["content"][:120] + "..." if len(entry["content"]) > 120 else entry["content"])
                console.print(table)
            else:
                console.print("[dim]No history yet.[/dim]")
            continue

        history.append({"role": "user", "content": user_input})

        with console.status("[bold cyan]KaliGuard AI is thinking...[/bold cyan]", spinner="dots"):
            try:
                response = agent.chat(user_input, session_id=session_id, history=history[:-1])
            except Exception as e:
                response = f"Error: {e}"

        history.append({"role": "assistant", "content": response})

        console.print(
            Panel(
                response,
                title="[bold cyan]KaliGuard AI[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )


@cli.command()
@click.pass_context
def status(ctx):
    """
    Show KaliGuard AI system status and installed tools.
    """
    cfg = ctx.obj["config"]

    console.print(Panel(
        f"[bold green]{cfg['agent']['name']}[/bold green] v{cfg['agent']['version']}\n"
        f"[dim]{cfg['agent']['description']}[/dim]",
        border_style="green",
    ))

    tools_to_check = [
        ("nmap", "Network scanner"),
        ("masscan", "Mass port scanner"),
        ("nikto", "Web vulnerability scanner"),
        ("gobuster", "Directory/file brute forcer"),
        ("sqlmap", "SQL injection tool"),
        ("hashcat", "Password recovery"),
        ("john", "Password cracker"),
        ("hydra", "Login brute forcer"),
        ("wireshark", "Packet analyzer"),
        ("tcpdump", "Packet capture"),
        ("aircrack-ng", "Wireless security"),
        ("volatility3", "Memory forensics"),
        ("ghidra", "Reverse engineering"),
        ("yara", "Malware detection"),
        ("metasploit-framework", "Exploitation framework"),
        ("snort", "Network IDS"),
    ]

    table = Table(title="Installed Tools", box=box.ROUNDED)
    table.add_column("Tool", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Status", style="bold")

    import subprocess
    for tool, desc in tools_to_check:
        try:
            result = subprocess.run(["which", tool], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                status_text = "[green]Installed[/green]"
            else:
                status_text = "[red]Not Found[/red]"
        except Exception:
            status_text = "[yellow]Unknown[/yellow]"
        table.add_row(tool, desc, status_text)

    console.print(table)

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key:
        key_display = api_key[:8] + "..." + api_key[-4:]
        api_status = f"[green]Set ({key_display})[/green]"
    else:
        api_status = "[red]Not Set (set ANTHROPIC_API_KEY)[/red]"

    config_table = Table(title="Configuration", box=box.ROUNDED)
    config_table.add_column("Setting", style="cyan")
    config_table.add_column("Value", style="white")
    config_table.add_row("AI Model", cfg["ai"]["model"])
    config_table.add_row("ANTHROPIC_API_KEY", api_status)
    config_table.add_row("Dry Run", str(cfg["security"]["dry_run"]))
    config_table.add_row("Allowed Networks", ", ".join(cfg["security"]["allowed_networks"]))
    config_table.add_row("Log Level", cfg["logging"]["log_level"])
    config_table.add_row("Report Output", cfg["reports"]["output_dir"])
    console.print(config_table)


def main():
    """Entry point for KaliGuard AI."""
    cli(obj={})


if __name__ == "__main__":
    main()
