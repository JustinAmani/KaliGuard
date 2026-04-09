#!/usr/bin/env python3
"""
KaliGuard AI - Network Monitoring Tools Module

Wraps tcpdump, tshark, arp-scan, netdiscover, snort, suricata, p0f, bettercap.

LEGAL: Authorized use only on networks you own or have explicit written permission to monitor.
"""

import subprocess
import shlex
import os
import logging
from datetime import datetime

logger = logging.getLogger("kaliguard.tools.network")


def _run_command(command: str, timeout: int = 120) -> tuple:
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


def tcpdump_capture(
    interface: str = "eth0",
    duration: int = 60,
    filter_expr: str = "",
    dry_run: bool = False
) -> dict:
    """
    Capture network packets using tcpdump.

    Args:
        interface: Network interface to capture on (e.g. eth0, wlan0, any)
        duration: Capture duration in seconds
        filter_expr: BPF filter expression (e.g. 'tcp port 80', 'host 192.168.1.1')
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    output_file = f"/tmp/kaliguard_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    filter_part = f"'{filter_expr}'" if filter_expr else ""
    command = f"tcpdump -i {interface} -w {output_file} -G {duration} -W 1 -nn -v {filter_part}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated tcpdump capture\n"
            f"Command: {command}\n\n"
            f"tcpdump: listening on {interface}, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n"
            f"Captured packets: 1847\n\n"
            f"Sample traffic (first 10 packets):\n"
            f"12:00:01.123456 IP 192.168.1.10.54321 > 192.168.1.1.80: Flags [S], seq 1234567, win 65535\n"
            f"12:00:01.124000 IP 192.168.1.1.80 > 192.168.1.10.54321: Flags [S.], seq 9876543, win 65535\n"
            f"12:00:01.124100 IP 192.168.1.10.54321 > 192.168.1.1.80: Flags [.], ack 9876544\n"
            f"12:00:01.125000 IP 192.168.1.10.54321 > 192.168.1.1.80: Flags [P.], length 412: HTTP: GET / HTTP/1.1\n"
            f"12:00:01.200000 ARP who-has 192.168.1.50 tell 192.168.1.1\n"
            f"12:00:01.200100 ARP reply 192.168.1.50 is-at aa:bb:cc:dd:ee:ff\n"
            f"12:00:02.000000 IP 192.168.1.200.33456 > 192.168.1.1.4444: Flags [P.] [SUSPICIOUS - unusual port]\n"
            f"12:00:02.100000 UDP 192.168.1.10.53 > 192.168.1.1.53: DNS query A www.example.com\n\n"
            f"[!] Suspicious connection detected: {interface} traffic to port 4444 (possible C2)\n"
            f"Capture saved to: {output_file}\n"
            f"Duration: {duration}s | Packets: 1847"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=duration + 30)
    success = code == 0
    if success:
        output_msg = f"Capture complete. File saved to: {output_file}\n{stdout}"
    else:
        output_msg = stdout
    return _build_result(success, command, output_msg, stderr if not success else "")


def tshark_capture(
    interface: str = "eth0",
    duration: int = 60,
    filter_expr: str = "",
    dry_run: bool = False
) -> dict:
    """
    Capture and analyze network packets using tshark (Wireshark CLI).

    Args:
        interface: Network interface to capture on
        duration: Capture duration in seconds
        filter_expr: Display/capture filter expression
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    output_file = f"/tmp/kaliguard_tshark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    filter_part = f"-f '{filter_expr}'" if filter_expr else ""
    command = f"tshark -i {interface} -a duration:{duration} -w {output_file} {filter_part} -V"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated tshark capture\n"
            f"Command: {command}\n\n"
            f"Capturing on '{interface}'\n"
            f"1234 packets captured\n\n"
            f"Protocol hierarchy statistics:\n"
            f"  Ethernet    : 100.0%\n"
            f"    IP        :  95.2%\n"
            f"      TCP     :  72.3%\n"
            f"        HTTP  :  18.4%\n"
            f"        TLS   :  45.6%\n"
            f"      UDP     :  22.9%\n"
            f"        DNS   :   8.7%\n"
            f"    ARP       :   4.8%\n\n"
            f"Notable connections:\n"
            f"  192.168.1.10:50123 -> 8.8.8.8:53      DNS queries (96 packets)\n"
            f"  192.168.1.10:54234 -> 93.184.216.34:80 HTTP (245 packets) [unencrypted]\n"
            f"  192.168.1.200:44567 -> 192.168.1.1:22  SSH brute force? (1823 packets)\n\n"
            f"[!] Potential SSH brute force detected from 192.168.1.200\n"
            f"Capture saved to: {output_file}"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=duration + 30)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def arp_scan(network: str, dry_run: bool = False) -> dict:
    """
    Discover live hosts on a network using ARP scanning.

    Args:
        network: Network CIDR range (e.g. 192.168.1.0/24)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"arp-scan --localnet {network} --retry=3"

    if dry_run:
        base = network.rsplit('.', 1)[0] if '/' in network else network
        output = (
            f"[DRY RUN] Simulated ARP scan\n"
            f"Command: {command}\n\n"
            f"Interface: eth0, type: EN10MB, MAC: 00:0c:29:ab:cd:ef, IPv4: 192.168.1.50\n"
            f"Starting arp-scan 1.10.0 with 256 hosts\n\n"
            f"192.168.1.1\t00:50:56:c0:00:01\tVMware, Inc.\n"
            f"192.168.1.10\taa:bb:cc:dd:ee:01\tIntel Corporate\n"
            f"192.168.1.11\taa:bb:cc:dd:ee:02\tAsusTeK Computer Inc.\n"
            f"192.168.1.20\taa:bb:cc:dd:ee:03\tRaspberry Pi Foundation\n"
            f"192.168.1.50\t00:0c:29:ab:cd:ef\tVMware, Inc. [THIS HOST]\n"
            f"192.168.1.100\taa:bb:cc:dd:ee:04\tHewlett Packard\n"
            f"192.168.1.200\tde:ad:be:ef:ca:fe\tUnknown [SUSPICIOUS - Random MAC]\n\n"
            f"7 hosts found. 7 packets sent, 7 packets received, 0 unanswered\n"
            f"[!] Suspicious host detected: 192.168.1.200 has a randomized MAC address"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=60)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def netdiscover_scan(network: str, dry_run: bool = False) -> dict:
    """
    Discover hosts on a network using netdiscover passive/active ARP scanning.

    Args:
        network: Network CIDR range (e.g. 192.168.1.0/24)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"netdiscover -r {network} -P"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated netdiscover scan\n"
            f"Command: {command}\n\n"
            f" Currently scanning: Finished!   |   Screen View: Unique Hosts\n\n"
            f"  IP            At MAC Address     Count     Len  MAC Vendor / Hostname\n"
            f" -----------------------------------------------------------------------------\n"
            f"  192.168.1.1   00:50:56:c0:00:01      1      60  VMware, Inc.\n"
            f"  192.168.1.10  aa:bb:cc:dd:ee:01      5     300  Intel Corp\n"
            f"  192.168.1.20  aa:bb:cc:dd:ee:02      3     180  Raspberry Pi\n"
            f"  192.168.1.100 aa:bb:cc:dd:ee:03      2     120  HP Inc.\n\n"
            f"4 hosts found in network {network}"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def snort_monitor(
    interface: str,
    config: str = "/etc/snort/snort.conf",
    dry_run: bool = False
) -> dict:
    """
    Monitor network traffic with Snort IDS for intrusion detection.

    Args:
        interface: Network interface to monitor
        config: Path to Snort configuration file
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"snort -i {interface} -c {config} -A console -l /var/log/snort/"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Snort IDS monitoring\n"
            f"Command: {command}\n\n"
            f"   ,,_     -*> Snort! <*-\n"
            f"  o\"  )~   Version 3.1.44.0\n"
            f"   ''''    By Martin Roesch & The Snort Team\n\n"
            f"--== Initialization Complete ==--\n\n"
            f"[**] [1:1000001:1] ET SCAN Nmap Scan Detected [**]\n"
            f"[Priority: 2] \n"
            f"04/09-12:00:01.123456 192.168.1.200:52345 -> 192.168.1.100:80\n"
            f"TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:60 DF\n\n"
            f"[**] [1:2001219:20] ET SCAN Potential SSH Scan [**]\n"
            f"[Priority: 2] \n"
            f"04/09-12:00:05.234567 192.168.1.200:33445 -> 192.168.1.1:22\n\n"
            f"[**] [1:2019284:4] ET POLICY Possible CVE-2021-44228 Log4j Header [**]\n"
            f"[Priority: 1] \n"
            f"04/09-12:00:10.345678 10.0.0.50:44312 -> 192.168.1.100:8080\n\n"
            f"Alerts generated: 3 | Packets analyzed: 15432"
        )
        return _build_result(True, command, output)

    if not os.path.exists(config):
        return _build_result(False, command, "", f"Snort config not found: {config}. Run: sudo apt install snort")

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def suricata_monitor(interface: str, dry_run: bool = False) -> dict:
    """
    Monitor network traffic using Suricata IDS/IPS.

    Args:
        interface: Network interface to monitor
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"suricata -i {interface} --pidfile /tmp/suricata.pid -l /var/log/suricata/"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Suricata IDS monitoring\n"
            f"Command: {command}\n\n"
            f"Suricata version 6.0.13\n"
            f"[*] Starting capture on interface {interface}\n"
            f"[*] Loading rules from /etc/suricata/rules/\n"
            f"[*] 35000 rules loaded\n\n"
            f"Alerts (JSON format):\n"
            f'{{\"timestamp\":\"2026-04-09T12:00:01\",\"event_type\":\"alert\",\"src_ip\":\"192.168.1.200\",\"dest_ip\":\"192.168.1.1\",\"proto\":\"TCP\",\"alert\":{{\"signature\":\"ET SCAN Nmap SYN Scan\",\"severity\":2}}}}\n'
            f'{{\"timestamp\":\"2026-04-09T12:00:05\",\"event_type\":\"alert\",\"src_ip\":\"192.168.1.200\",\"dest_ip\":\"192.168.1.100\",\"proto\":\"HTTP\",\"alert\":{{\"signature\":\"ET EXPLOIT Log4j RCE Attempt\",\"severity\":1}}}}\n'
            f'{{\"timestamp\":\"2026-04-09T12:00:10\",\"event_type\":\"alert\",\"src_ip\":\"10.0.0.50\",\"dest_ip\":\"192.168.1.1\",\"proto\":\"SSH\",\"alert\":{{\"signature\":\"ET BRUTE SSH Brute Force\",\"severity\":2}}}}\n\n'
            f"[!] 3 alerts generated. Check /var/log/suricata/fast.log for details."
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def p0f_fingerprint(interface: str, dry_run: bool = False) -> dict:
    """
    Perform passive OS fingerprinting using p0f.

    Args:
        interface: Network interface to monitor
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"p0f -i {interface} -o /tmp/p0f_output.log"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated p0f passive fingerprinting\n"
            f"Command: {command}\n\n"
            f"--- p0f 3.09b by Michal Zalewski <lcamtuf@coredump.cx> ---\n\n"
            f"[+] Listening on interface {interface}\n\n"
            f".-[ 192.168.1.10/45123 -> 192.168.1.1/80 (syn) ]-\n"
            f"|\n"
            f"| client   = 192.168.1.10/45123\n"
            f"| os       = Windows NT kernel 6.x\n"
            f"| dist     = 0\n"
            f"| params   = generic\n"
            f"| raw_sig  = 4:128+0:0:65535:mss*20,10:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0\n"
            f"`----\n\n"
            f".-[ 192.168.1.20/33456 -> 192.168.1.1/22 (syn) ]-\n"
            f"|\n"
            f"| client   = 192.168.1.20/33456\n"
            f"| os       = Linux 3.11-4.x\n"
            f"| dist     = 0\n"
            f"| raw_sig  = 4:64+0:0:29200:mss*10,6:mss,sackOK,ts,nop,ws:df,id+:0\n"
            f"`----\n\n"
            f"Fingerprinted 5 hosts. Results saved to /tmp/p0f_output.log"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def bettercap_scan(interface: str, dry_run: bool = False) -> dict:
    """
    Run bettercap network scanner for host discovery and protocol analysis.

    Args:
        interface: Network interface to use
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"bettercap -iface {interface} -eval 'net.probe on; sleep 10; net.show; exit'"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated bettercap scan\n"
            f"Command: {command}\n\n"
            f"bettercap v2.32.0 (built for linux/amd64 with go1.18)\n"
            f"[sys.log] [inf] bettercap v2.32.0 starting...\n"
            f"[net.recon] discovered 192.168.1.1 (gateway)\n"
            f"[net.recon] discovered 192.168.1.10 (Windows)\n"
            f"[net.recon] discovered 192.168.1.20 (Linux)\n"
            f"[net.recon] discovered 192.168.1.100 (Linux - Web Server)\n\n"
            f"┌─────────────────────────────────────────────────────────────────┐\n"
            f"│ Hosts                                                           │\n"
            f"├──────────────┬───────────────────┬──────────┬──────────────────┤\n"
            f"│ IP           │ MAC               │ Hostname │ Vendor           │\n"
            f"├──────────────┼───────────────────┼──────────┼──────────────────┤\n"
            f"│ 192.168.1.1  │ 00:50:56:c0:00:01 │ gateway  │ VMware           │\n"
            f"│ 192.168.1.10 │ aa:bb:cc:dd:ee:01 │ workst01 │ Intel Corp       │\n"
            f"│ 192.168.1.20 │ aa:bb:cc:dd:ee:02 │ raspi01  │ Raspberry Pi     │\n"
            f"│ 192.168.1.100│ aa:bb:cc:dd:ee:03 │ webserv  │ Hewlett Packard  │\n"
            f"└──────────────┴───────────────────┴──────────┴──────────────────┘\n"
            f"4 hosts discovered"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")
