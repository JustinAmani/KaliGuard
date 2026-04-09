#!/usr/bin/env python3
"""
KaliGuard AI - Anonymity & Privacy Tools Module

Wraps Tor, anonsurf, macchanger, proxychains, and IP checking utilities.

Used for testing anonymization defenses and privacy configurations.

LEGAL: Authorized use only. Do not use these tools to evade detection during unauthorized activities.
"""

import subprocess
import shlex
import os
import logging
import requests
from datetime import datetime

logger = logging.getLogger("kaliguard.tools.anonymity")


def _run_command(command: str, timeout: int = 60) -> tuple:
    """Execute a shell command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except FileNotFoundError as e:
        return "", f"Tool not found: {e}", -1
    except Exception as e:
        return "", str(e), -1


def _build_result(success: bool, command: str, output: str, error: str = "") -> dict:
    """Build a standardized result dictionary."""
    return {
        "success": success,
        "command": command,
        "output": output,
        "error": error,
        "timestamp": datetime.now().isoformat()
    }


def tor_status(dry_run: bool = False) -> dict:
    """
    Check the status of the Tor service.

    Args:
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = "systemctl status tor"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Tor status check\n"
            f"Command: {command}\n\n"
            f"● tor.service - Anonymizing overlay network for TCP (multi-instance-master)\n"
            f"     Loaded: loaded (/lib/systemd/system/tor.service; enabled)\n"
            f"     Active: active (running) since 2026-04-09 12:00:00 UTC\n"
            f"    Process: ExecStartPre=/usr/bin/install -Z -m 02755 -o debian-tor -g debian-tor -d /run/tor\n"
            f"   Main PID: 1234 (tor)\n"
            f"     Status: \"Bootstrapped 100% (done): Done\"\n"
            f"      Tasks: 1 (limit: 4096)\n"
            f"     Memory: 42.5M\n"
            f"        CPU: 2.3s\n\n"
            f"Tor is running and bootstrapped to 100%\n"
            f"SOCKS proxy available on: 127.0.0.1:9050\n"
            f"Use: proxychains [command] to route through Tor"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=30)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def anonsurf_start(dry_run: bool = False) -> dict:
    """
    Start AnonSurf to route all traffic through Tor anonymization network.

    AnonSurf is a Kali Linux tool that routes all system traffic through Tor.

    Args:
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = "anonsurf start"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated AnonSurf start\n"
            f"Command: {command}\n\n"
            f"[*] Starting AnonSurf\n"
            f"[*] Deleting logs...\n"
            f"[OK] logs deleted!\n"
            f"[*] Setting iptables rules...\n"
            f"[OK] iptables rules set\n"
            f"[*] Starting Tor service...\n"
            f"[OK] Tor started\n"
            f"[*] Waiting for Tor bootstrapping...\n"
            f"[OK] Bootstrapped 100% (done): Done\n\n"
            f"[+] AnonSurf is running\n"
            f"[+] All traffic is now routed through Tor\n\n"
            f"Your new IP: 185.220.101.24 (Tor exit node)\n"
            f"Stop with: anonsurf stop"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=60)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def anonsurf_stop(dry_run: bool = False) -> dict:
    """
    Stop AnonSurf and restore normal network routing.

    Args:
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = "anonsurf stop"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated AnonSurf stop\n"
            f"Command: {command}\n\n"
            f"[*] Stopping AnonSurf\n"
            f"[*] Removing iptables rules...\n"
            f"[OK] iptables rules removed\n"
            f"[*] Stopping Tor service...\n"
            f"[OK] Tor stopped\n"
            f"[*] Deleting logs...\n"
            f"[OK] logs deleted!\n"
            f"[*] Restoring DNS...\n"
            f"[OK] DNS restored\n\n"
            f"[+] AnonSurf stopped\n"
            f"[+] Traffic is now routing normally"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=60)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def macchanger_random(interface: str, dry_run: bool = False) -> dict:
    """
    Change the MAC address of a network interface to a random value using macchanger.

    Useful for testing network access controls that filter by MAC address.

    Args:
        interface: Network interface to change MAC address on (e.g. eth0, wlan0)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"macchanger -r {interface}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated macchanger MAC randomization\n"
            f"Command: {command}\n\n"
            f"Permanent MAC: aa:bb:cc:dd:ee:ff (Intel Corporate)\n"
            f"Current MAC:   aa:bb:cc:dd:ee:ff (Intel Corporate)\n"
            f"New MAC:       de:ad:be:ef:ca:fe (Unknown)\n\n"
            f"[+] MAC address changed to: de:ad:be:ef:ca:fe\n\n"
            f"Note: This change is temporary and will revert on interface restart or reboot.\n"
            f"To restore original MAC: macchanger -p {interface}"
        )
        return _build_result(True, command, output)

    # Bring interface down, change MAC, bring back up
    down_stdout, _, _ = _run_command(f"ip link set {interface} down", timeout=10)
    stdout, stderr, code = _run_command(command, timeout=30)
    up_stdout, _, _ = _run_command(f"ip link set {interface} up", timeout=10)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def proxychains_config(proxy_list: list, dry_run: bool = False) -> dict:
    """
    Configure proxychains with a list of proxy servers.

    Proxychains routes TCP connections through proxy chains (SOCKS4/5, HTTP).

    Args:
        proxy_list: List of proxy strings in format ['socks5 127.0.0.1 9050', 'http 192.168.1.1 8080']
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    config_path = "/etc/proxychains4.conf"
    command = f"cat {config_path}"

    if dry_run:
        proxies_str = "\n".join(f"  {p}" for p in proxy_list)
        output = (
            f"[DRY RUN] Simulated proxychains configuration\n"
            f"Config file: {config_path}\n\n"
            f"Configuring proxychains with {len(proxy_list)} proxies:\n"
            f"{proxies_str}\n\n"
            f"Generated /etc/proxychains4.conf:\n"
            f"  strict_chain\n"
            f"  proxy_dns\n"
            f"  tcp_read_time_out 15000\n"
            f"  tcp_connect_time_out 8000\n\n"
            f"  [ProxyList]\n"
            f"{proxies_str}\n\n"
            f"[+] Proxychains configured with {len(proxy_list)} proxies\n"
            f"Usage: proxychains4 [command]\n"
            f"Example: proxychains4 nmap -sT 192.168.1.1"
        )
        return _build_result(True, command, output)

    # Build proxychains config
    config_content = "strict_chain\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n\n[ProxyList]\n"
    for proxy in proxy_list:
        config_content += f"{proxy}\n"

    try:
        with open(config_path, 'w') as f:
            f.write(config_content)
        output = f"Proxychains configured with {len(proxy_list)} proxies.\nConfig saved to {config_path}"
        return _build_result(True, command, output)
    except PermissionError:
        return _build_result(False, command, "", f"Permission denied writing to {config_path}. Run as root.")
    except Exception as e:
        return _build_result(False, command, "", str(e))


def check_ip(dry_run: bool = False) -> dict:
    """
    Check the current external IP address and geolocation.

    Useful for verifying anonymization is working correctly.

    Args:
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = "curl -s https://ipinfo.io/json"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated IP check\n"
            f"Command: {command}\n\n"
            f"Current IP Information:\n"
            f"  IP:       185.220.101.24\n"
            f"  Hostname: tor-exit.example.com\n"
            f"  City:     Frankfurt\n"
            f"  Region:   Hesse\n"
            f"  Country:  DE\n"
            f"  Location: 50.1109, 8.6821\n"
            f"  Org:      AS24940 Hetzner Online GmbH\n"
            f"  Timezone: Europe/Berlin\n\n"
            f"[+] Traffic appears to be routed through Tor exit node\n"
            f"[+] Your real IP is hidden\n\n"
            f"Original IP: [hidden behind Tor]"
        )
        return _build_result(True, command, output)

    try:
        response = requests.get("https://ipinfo.io/json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            output = (
                f"Current IP Information:\n"
                f"  IP:       {data.get('ip', 'Unknown')}\n"
                f"  Hostname: {data.get('hostname', 'Unknown')}\n"
                f"  City:     {data.get('city', 'Unknown')}\n"
                f"  Region:   {data.get('region', 'Unknown')}\n"
                f"  Country:  {data.get('country', 'Unknown')}\n"
                f"  Location: {data.get('loc', 'Unknown')}\n"
                f"  Org:      {data.get('org', 'Unknown')}\n"
                f"  Timezone: {data.get('timezone', 'Unknown')}"
            )
            return _build_result(True, command, output)
        else:
            return _build_result(False, command, "", f"HTTP {response.status_code} from ipinfo.io")
    except requests.RequestException as e:
        # Fallback to curl
        stdout, stderr, code = _run_command(command, timeout=15)
        success = code == 0
        return _build_result(success, command, stdout, stderr if not success else "")
    except Exception as e:
        return _build_result(False, command, "", str(e))
