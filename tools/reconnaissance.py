#!/usr/bin/env python3
"""
KaliGuard AI - Reconnaissance Tools Module

Wraps common Kali Linux reconnaissance tools: nmap, masscan, nikto,
gobuster, theharvester, whois, dnsenum, subfinder, and more.

LEGAL: Authorized use only on networks/systems you own or have explicit written permission to test.
"""

import subprocess
import shlex
import json
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("kaliguard.tools.recon")


def _run_command(command: str, timeout: int = 300) -> tuple:
    """
    Execute a shell command and return (stdout, stderr, returncode).

    Args:
        command: Shell command string to execute
        timeout: Timeout in seconds

    Returns:
        Tuple of (stdout, stderr, returncode)
    """
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
        return "", f"Tool not found: {e}. Install it with: sudo apt install {command.split()[0]}", -1
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


def nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "SYN", dry_run: bool = False) -> dict:
    """
    Run an Nmap network scan against a target.

    Args:
        target: IP address, hostname, or CIDR range to scan
        ports: Port range (e.g. '1-1000', '80,443,8080', '-' for all ports)
        scan_type: Scan type - SYN, TCP, UDP, ACK, FIN, XMAS, NULL, PING
        dry_run: If True, return simulated output without executing

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    scan_flags = {
        "SYN": "-sS",
        "TCP": "-sT",
        "UDP": "-sU",
        "ACK": "-sA",
        "FIN": "-sF",
        "XMAS": "-sX",
        "NULL": "-sN",
        "PING": "-sn",
    }
    flag = scan_flags.get(scan_type.upper(), "-sS")
    command = f"nmap {flag} -p {ports} -sV -sC -O --open -T4 {target}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated nmap scan\n"
            f"Command: {command}\n\n"
            f"Starting Nmap 7.94 ( https://nmap.org )\n"
            f"Nmap scan report for {target}\n"
            f"Host is up (0.0012s latency).\n"
            f"PORT     STATE SERVICE   VERSION\n"
            f"22/tcp   open  ssh       OpenSSH 8.9p1 Ubuntu\n"
            f"80/tcp   open  http      Apache httpd 2.4.52\n"
            f"443/tcp  open  https     Apache httpd 2.4.52\n"
            f"3306/tcp open  mysql     MySQL 8.0.32\n"
            f"OS: Linux 5.x\n"
            f"Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=300)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def masscan_scan(target: str, ports: str = "1-65535", rate: int = 1000, dry_run: bool = False) -> dict:
    """
    Run Masscan for fast large-scale port scanning.

    Args:
        target: IP address or CIDR range
        ports: Port range to scan
        rate: Packets per second (higher = faster but less accurate)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"masscan {target} -p{ports} --rate={rate} --open"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated masscan\n"
            f"Command: {command}\n\n"
            f"Starting masscan 1.3.2 (http://bit.ly/14GZzcT)\n"
            f"Initiating SYN Stealth Scan\n"
            f"Discovered open port 22/tcp on {target.split('/')[0]}\n"
            f"Discovered open port 80/tcp on {target.split('/')[0]}\n"
            f"Discovered open port 443/tcp on {target.split('/')[0]}\n"
            f"Scan done: 1 IP addresses scanned in 2.34 seconds"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def theharvester_scan(domain: str, sources: str = "all", dry_run: bool = False) -> dict:
    """
    Run theHarvester for OSINT email and subdomain harvesting.

    Args:
        domain: Target domain to harvest information about
        sources: Data sources to query (e.g. 'google,bing,linkedin' or 'all')
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    if sources == "all":
        sources = "google,bing,baidu,duckduckgo,linkedin,yahoo"
    command = f"theHarvester -d {domain} -b {sources} -l 100"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated theHarvester scan\n"
            f"Command: {command}\n\n"
            f"*******************************************************************\n"
            f"*  _   _                                            _             *\n"
            f"* | |_| |__   ___  /\\  /\\__ _ _ ____   _____  ___| |_ ___ _ __  *\n"
            f"*  | __| '_ \\ / _ \\/ /_/ / _` | '__\\ \\ / / _ \\/ __| __/ _ \\ '__| *\n"
            f"*  | |_| | | |  __/ __  / (_| | |   \\ V /  __/\\__ \\ ||  __/ |    *\n"
            f"*   \\__|_| |_|\\___\\/ /_/ \\__,_|_|    \\_/ \\___||___/\\__\\___|_|    *\n"
            f"*                                                                  *\n"
            f"*******************************************************************\n\n"
            f"[*] Target: {domain}\n\n"
            f"[*] Emails found:\n"
            f"\tadmin@{domain}\n"
            f"\tinfo@{domain}\n"
            f"\tsecurity@{domain}\n\n"
            f"[*] Hosts found:\n"
            f"\twww.{domain}:192.168.1.10\n"
            f"\tmail.{domain}:192.168.1.11\n"
            f"\tvpn.{domain}:192.168.1.12"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=300)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def whois_lookup(target: str, dry_run: bool = False) -> dict:
    """
    Perform a WHOIS lookup on a domain or IP address.

    Args:
        target: Domain name or IP address to look up
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"whois {target}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated WHOIS lookup\n"
            f"Command: {command}\n\n"
            f"Domain Name: {target.upper()}\n"
            f"Registrar: Example Registrar, Inc.\n"
            f"Updated Date: 2025-01-15\n"
            f"Creation Date: 2020-03-10\n"
            f"Registry Expiry Date: 2026-03-10\n"
            f"Name Server: ns1.example.com\n"
            f"Name Server: ns2.example.com\n"
            f"DNSSEC: unsigned\n"
            f"Registrant Organization: Example Corp\n"
            f"Registrant Country: MU"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=30)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def dns_enum(target: str, dry_run: bool = False) -> dict:
    """
    Perform DNS enumeration including zone transfer attempt, subdomain brute force.

    Args:
        target: Domain name to enumerate
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"dnsenum --noreverse --threads 5 {target}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated DNS enumeration\n"
            f"Command: {command}\n\n"
            f"dnsenum VERSION:1.2.6\n\n"
            f"-----   {target}   -----\n\n"
            f"Host's addresses:\n"
            f"{target}.\t\t300\tIN\tA\t192.168.1.10\n\n"
            f"Name Servers:\n"
            f"ns1.{target}.\t300\tIN\tA\t192.168.1.1\n"
            f"ns2.{target}.\t300\tIN\tA\t192.168.1.2\n\n"
            f"Mail (MX) Servers:\n"
            f"mail.{target}.\t300\tIN\tA\t192.168.1.11\n\n"
            f"Zone Transfer for {target}:\n"
            f"AXFR record query failed: REFUSED"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def subfinder_scan(domain: str, dry_run: bool = False) -> dict:
    """
    Discover subdomains using subfinder passive reconnaissance tool.

    Args:
        domain: Target domain to find subdomains for
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"subfinder -d {domain} -silent -o /tmp/subfinder_{domain}.txt"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated subfinder scan\n"
            f"Command: {command}\n\n"
            f"www.{domain}\n"
            f"mail.{domain}\n"
            f"vpn.{domain}\n"
            f"dev.{domain}\n"
            f"staging.{domain}\n"
            f"api.{domain}\n"
            f"admin.{domain}\n"
            f"[INF] Found 7 subdomains for {domain}"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def shodan_search(query: str, dry_run: bool = False) -> dict:
    """
    Search Shodan for internet-exposed devices matching a query.

    Args:
        query: Shodan search query (e.g. 'port:22 country:MU')
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"shodan search --fields ip_str,port,org,hostnames \"{query}\""

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Shodan search\n"
            f"Command: {command}\n\n"
            f"NOTE: Shodan search requires API key (shodan init YOUR_API_KEY)\n\n"
            f"Query: {query}\n"
            f"Results (simulated):\n"
            f"192.168.1.100\t22\tExample ISP\thostname.example.com\n"
            f"192.168.1.101\t80\tExample ISP\twww.example.com\n"
            f"Total: 2 results found"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=60)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def nikto_scan(target: str, dry_run: bool = False) -> dict:
    """
    Run Nikto web server vulnerability scanner against a target.

    Args:
        target: Target URL or IP address (e.g. http://192.168.1.100)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    if not target.startswith("http"):
        target = f"http://{target}"
    command = f"nikto -h {target} -C all -Format txt"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Nikto scan\n"
            f"Command: {command}\n\n"
            f"- Nikto v2.1.6\n"
            f"---------------------------------------------------------------------------\n"
            f"+ Target IP:          192.168.1.100\n"
            f"+ Target Hostname:    {target}\n"
            f"+ Target Port:        80\n"
            f"+ Start Time:         2026-04-09 12:00:00\n"
            f"---------------------------------------------------------------------------\n"
            f"+ Server: Apache/2.4.52 (Ubuntu)\n"
            f"+ /: The anti-clickjacking X-Frame-Options header is not present.\n"
            f"+ /: The X-XSS-Protection header is not defined.\n"
            f"+ /: The X-Content-Type-Options header is not set.\n"
            f"+ /phpMyAdmin/: phpMyAdmin directory found.\n"
            f"+ /admin/: Admin directory accessible.\n"
            f"+ OSVDB-3092: /README: README file found.\n"
            f"+ 8702 requests: 0 error(s) and 6 item(s) reported\n"
            f"+ End Time: 2026-04-09 12:05:00 (300 seconds)"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=300)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def gobuster_scan(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    dry_run: bool = False
) -> dict:
    """
    Run Gobuster directory/file brute forcing against a web server.

    Args:
        target: Target URL (e.g. http://192.168.1.100)
        wordlist: Path to wordlist file
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    if not target.startswith("http"):
        target = f"http://{target}"
    command = f"gobuster dir -u {target} -w {wordlist} -t 50 --no-error -q"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Gobuster scan\n"
            f"Command: {command}\n\n"
            f"/admin                (Status: 200) [Size: 4521]\n"
            f"/backup               (Status: 403) [Size: 277]\n"
            f"/config               (Status: 403) [Size: 277]\n"
            f"/images               (Status: 301) [Size: 316]\n"
            f"/login                (Status: 200) [Size: 2048]\n"
            f"/phpMyAdmin           (Status: 200) [Size: 8547]\n"
            f"/upload               (Status: 301) [Size: 316]\n"
            f"/wp-admin             (Status: 301) [Size: 316]\n"
            f"\nFinished: 8 directories/files found"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def enum4linux_scan(target: str, dry_run: bool = False) -> dict:
    """
    Run enum4linux for SMB/NetBIOS enumeration of Windows/Samba targets.

    Args:
        target: Target IP address (Windows/Samba host)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"enum4linux -a {target}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated enum4linux scan\n"
            f"Command: {command}\n\n"
            f"Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ )\n\n"
            f"[*] Enumerating Workgroup/Domain on {target}\n"
            f"\tWorkgroup: WORKGROUP\n\n"
            f"[*] Getting OS information\n"
            f"\tOS: Windows Server 2019 (10.0)\n\n"
            f"[*] Share Enumeration on {target}\n"
            f"\tSharname   Type  Comment\n"
            f"\t--------   ----  -------\n"
            f"\tIPC$       IPC   Remote IPC\n"
            f"\tADMIN$     Disk  Remote Admin\n"
            f"\tC$         Disk  Default share\n"
            f"\tshared     Disk  Company Files\n\n"
            f"[*] Password Policy Information\n"
            f"\tMinimum password length: 8\n"
            f"\tPassword history length: 24\n"
            f"\tMaximum password age: 42 days\n"
            f"\tAccount lockout threshold: 5\n"
            f"enum4linux complete on {target}"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def wpscan(target: str, dry_run: bool = False) -> dict:
    """
    Run WPScan WordPress vulnerability scanner against a WordPress site.

    Args:
        target: Target URL of WordPress site
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    if not target.startswith("http"):
        target = f"http://{target}"
    command = f"wpscan --url {target} --enumerate vp,vt,u --no-update"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated WPScan\n"
            f"Command: {command}\n\n"
            f"_______________________________________________________________\n"
            f"         __          _______   _____\n"
            f"         \\ \\        / /  __ \\ / ____|\n"
            f"          \\ \\  /\\  / /| |__) | (___   ___  __ _ _ __ ®\n"
            f"           \\ \\/  \\/ / |  ___/ \\___ \\ / __|/ _` | '_ \\\n"
            f"            \\  /\\  /  | |     ____) | (__| (_| | | | |\n"
            f"             \\/  \\/   |_|    |_____/ \\___|\\__,_|_| |_|\n\n"
            f"[*] URL: {target}\n"
            f"[+] WordPress version: 6.4.2 (insecure)\n"
            f"[!] 3 vulnerabilities identified:\n"
            f"  [!] CVE-2024-1234 - XSS in core\n"
            f"  [!] CVE-2024-5678 - SQLi in plugin Contact Form 7\n"
            f"  [!] CVE-2024-9999 - CSRF in wp-admin\n"
            f"[+] Users: admin, editor, author\n"
            f"Scan completed in 45 seconds"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=300)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")
