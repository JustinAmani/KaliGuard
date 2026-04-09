#!/usr/bin/env python3
"""
KaliGuard AI - Wireless Security Tools Module

Wraps airmon-ng, airodump-ng, aircrack-ng, kismet, wifite, and reaver.

LEGAL: Authorized use only on wireless networks you own or have explicit written permission to test.
"""

import subprocess
import shlex
import os
import logging
from datetime import datetime

logger = logging.getLogger("kaliguard.tools.wireless")


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


def airmon_start(interface: str, dry_run: bool = False) -> dict:
    """
    Start monitor mode on a wireless interface using airmon-ng.

    Monitor mode is required for packet capture and injection on wireless networks.

    Args:
        interface: Wireless interface to put in monitor mode (e.g. wlan0)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"airmon-ng start {interface}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated airmon-ng monitor mode start\n"
            f"Command: {command}\n\n"
            f"Found 2 processes that could cause trouble.\n"
            f"Kill them using 'airmon-ng check kill' before putting\n"
            f"the card in monitor mode, they will interfere by changing channels\n"
            f"and sometimes putting the interface back in managed mode\n\n"
            f"  PID Name\n"
            f"    1 NetworkManager\n"
            f" 1234 wpa_supplicant\n\n"
            f"PHY     Interface       Driver          Chipset\n"
            f"phy0    {interface}     ath9k_htc       Atheros AR9271 802.11n\n\n"
            f"                (mac80211 monitor mode vif enabled for [{interface}] on [mon0])\n"
            f"                (mac80211 station mode vif disabled for [{interface}])\n\n"
            f"Monitor mode started on: {interface}mon\n"
            f"Interface {interface}mon is ready for capture."
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=30)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def airodump_scan(interface: str, duration: int = 60, dry_run: bool = False) -> dict:
    """
    Scan for nearby wireless networks using airodump-ng.

    Captures WPA handshakes and discovers APs/clients.

    Args:
        interface: Wireless interface in monitor mode (e.g. wlan0mon)
        duration: Scan duration in seconds
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    output_file = f"/tmp/kaliguard_wifi_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    command = f"airodump-ng {interface} -w {output_file} --output-format csv"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated airodump-ng scan\n"
            f"Command: {command}\n\n"
            f" BSSID              PWR  Beacons  #Data  #/s  CH  MB   ENC CIPHER AUTH ESSID\n\n"
            f" AA:BB:CC:DD:EE:01  -45  150      423    12   6   54e  WPA2 CCMP   PSK  HomeNetwork\n"
            f" AA:BB:CC:DD:EE:02  -67  89       12     0    1   54e  WPA2 CCMP   PSK  OfficeWifi\n"
            f" AA:BB:CC:DD:EE:03  -72  43       0      0    11  54e  WEP  WEP        OldRouter [WEAK SECURITY]\n"
            f" AA:BB:CC:DD:EE:04  -80  12       0      0    6   54e  OPN             OpenNetwork [NO SECURITY]\n"
            f" AA:BB:CC:DD:EE:05  -55  200      89     4    6   54e  WPA2 CCMP   MGT CorporateWPA2-Enterprise\n\n"
            f" BSSID              STATION            PWR   Rate   Lost  Frames  Probe\n\n"
            f" AA:BB:CC:DD:EE:01  11:22:33:44:55:66  -48   54e-54  0     123\n"
            f" AA:BB:CC:DD:EE:02  77:88:99:AA:BB:CC  -70   11e-11  0     45\n\n"
            f"[!] WEP network detected: OldRouter - WEP is broken, upgrade to WPA2/WPA3\n"
            f"[!] Open network detected: OpenNetwork - No encryption\n"
            f"[!] WPA handshake captured for: HomeNetwork\n"
            f"Scan saved to: {output_file}-01.csv"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=duration + 10)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def aircrack_crack(cap_file: str, wordlist: str, dry_run: bool = False) -> dict:
    """
    Attempt to crack WPA/WEP keys from a captured handshake file using aircrack-ng.

    Args:
        cap_file: Path to .cap file containing captured WPA handshake or WEP IVs
        wordlist: Path to wordlist file for WPA cracking
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"aircrack-ng {cap_file} -w {wordlist}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated aircrack-ng WPA crack\n"
            f"Command: {command}\n\n"
            f"Opening {cap_file}\n"
            f"Read 15234 packets.\n\n"
            f"   #  BSSID              ESSID                     Encryption\n\n"
            f"   1  AA:BB:CC:DD:EE:01  HomeNetwork               WPA (1 handshake)\n\n"
            f"Choosing first network as target.\n\n"
            f"Opening {cap_file}\n"
            f"Reading packets, please wait...\n"
            f"Opening {wordlist}\n"
            f"                               Aircrack-ng 1.7\n\n"
            f"      [00:02:33] 1512340/14344391 keys tested (10232.45 k/s)\n\n"
            f"      Time left: 22 minutes, 30 seconds                    10.54%\n\n"
            f"                         KEY FOUND! [ password123 ]\n\n"
            f"      Master Key     : A1 B2 C3 D4 E5 F6 07 08 09 10 11 12 13 14 15 16\n"
            f"                       17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32\n\n"
            f"      Transient Key  : ...\n\n"
            f"[!] WPA key cracked: password123 - This is a WEAK password!"
        )
        return _build_result(True, command, output)

    if not os.path.exists(cap_file):
        return _build_result(False, command, "", f"Capture file not found: {cap_file}")
    if not os.path.exists(wordlist):
        return _build_result(False, command, "", f"Wordlist not found: {wordlist}")

    stdout, stderr, code = _run_command(command, timeout=3600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def kismet_scan(interface: str, dry_run: bool = False) -> dict:
    """
    Run Kismet wireless network detector and intrusion detection system.

    Args:
        interface: Wireless interface to use for scanning
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"kismet --no-ncurses -c {interface} --log-title kaliguard"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Kismet wireless scan\n"
            f"Command: {command}\n\n"
            f"INFO: Starting Kismet 2022-01-R3\n"
            f"INFO: Loading config files from /etc/kismet/\n"
            f"INFO: Starting Kismet web interface on port 2501\n"
            f"INFO: Added datasource '{interface}'\n\n"
            f"Discovered networks:\n"
            f"  ESSID: HomeNetwork    BSSID: AA:BB:CC:DD:EE:01  CH:6   WPA2\n"
            f"  ESSID: OfficeWifi     BSSID: AA:BB:CC:DD:EE:02  CH:1   WPA2\n"
            f"  ESSID: OldRouter      BSSID: AA:BB:CC:DD:EE:03  CH:11  WEP  [VULNERABLE]\n"
            f"  ESSID: OpenNetwork    BSSID: AA:BB:CC:DD:EE:04  CH:6   OPEN [VULNERABLE]\n\n"
            f"Detected devices: 8 clients\n"
            f"Detected probes: 15 probe requests\n"
            f"Access the web interface at http://localhost:2501\n"
            f"Log saved to: ./kaliguard-[timestamp].kismet"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def wifite_scan(interface: str, dry_run: bool = False) -> dict:
    """
    Run wifite automated wireless attack tool for WPA/WEP auditing.

    Args:
        interface: Wireless interface to use
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"wifite --interface {interface} --kill --dict /usr/share/wordlists/rockyou.txt"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated wifite scan\n"
            f"Command: {command}\n\n"
            f"     .;'                     `;,\n"
            f"    .;' .;'             `;, `;,\n"
            f"   .;' .;'   wifite 2   `;, `;,\n"
            f"  .;' .;'               `;, `;,\n"
            f"     .;'                   `;,\n\n"
            f" [+] scanning for targets (3 seconds)...\n\n"
            f" NUM  ESSID              CH  ENCR   POWER  WPS  CLIENT\n"
            f"  1   HomeNetwork        6   WPA2   -45db  YES  YES\n"
            f"  2   OfficeWifi         1   WPA2   -67db  NO   NO\n"
            f"  3   OldRouter          11  WEP    -72db  NO   NO\n\n"
            f" [+] Selected target: HomeNetwork (WPA2)\n"
            f" [+] Capturing WPA handshake from HomeNetwork...\n"
            f" [+] Handshake captured!\n"
            f" [+] Cracking WPA handshake for HomeNetwork\n"
            f" [+] KEY FOUND: password123\n\n"
            f"Cracked 1 network. Summary saved to cracked.txt"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def reaver_attack(bssid: str, interface: str, dry_run: bool = False) -> dict:
    """
    Test WPS PIN vulnerability using Reaver brute force attack.

    Targets routers with WPS enabled that are vulnerable to the Pixie Dust attack
    or standard WPS PIN brute force.

    Args:
        bssid: Target AP BSSID (MAC address) to attack
        interface: Wireless interface in monitor mode
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"reaver -i {interface} -b {bssid} -vv -K 1"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Reaver WPS attack\n"
            f"Command: {command}\n\n"
            f"Reaver v1.6.5 WiFi Protected Setup Attack Tool\n"
            f"Copyright (c) 2011, Tactical Network Solutions, Craig Heffner\n\n"
            f"[+] Waiting for beacon from {bssid}\n"
            f"[+] Received beacon from {bssid}\n"
            f"[+] Associated with {bssid} (ESSID: HomeNetwork)\n"
            f"[+] Trying Pixie Dust attack...\n"
            f"[Pixie-Dust] WPS pin: 12345678\n\n"
            f"[+] WPS PIN: '12345678'\n"
            f"[+] WPA PSK: 'password123'\n"
            f"[+] AP SSID: 'HomeNetwork'\n\n"
            f"[!] WPS vulnerability confirmed! WPS should be disabled on this router."
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")
