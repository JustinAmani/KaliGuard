#!/usr/bin/env python3
"""
KaliGuard AI - Password Cracking & Brute Force Tools Module

Wraps hashcat, john the ripper, hydra, medusa, crunch, cewl, and hashid.

LEGAL: Authorized use only on hashes and systems you own or have explicit written permission to test.
"""

import subprocess
import shlex
import os
import logging
from datetime import datetime

logger = logging.getLogger("kaliguard.tools.cracking")


def _run_command(command: str, timeout: int = 600) -> tuple:
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


def hashcat_crack(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    hash_type: str = "0",
    dry_run: bool = False
) -> dict:
    """
    Crack password hashes using Hashcat GPU-accelerated cracking.

    Common hash types:
    - 0: MD5
    - 100: SHA1
    - 1400: SHA256
    - 1000: NTLM
    - 500: md5crypt (Unix $1$)
    - 1800: sha512crypt (Unix $6$)
    - 2500: WPA/WPA2

    Args:
        hash_file: Path to file containing hashes (one per line)
        wordlist: Path to password wordlist file
        hash_type: Hashcat hash type code (default "0" = MD5)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"hashcat -m {hash_type} -a 0 {hash_file} {wordlist} --force --status"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated hashcat cracking\n"
            f"Command: {command}\n\n"
            f"hashcat (v6.2.6) starting...\n\n"
            f"CUDA API (CUDA 11.7)\n"
            f"* Device #1: NVIDIA GeForce RTX 3080, 10237/10239 MB\n\n"
            f"Minimum password length supported by kernel: 0\n"
            f"Maximum password length supported by kernel: 256\n\n"
            f"Hashes: 5 digests; 5 unique digests, 1 unique salts\n"
            f"Bitmaps: 16 bits, 65536 entries\n"
            f"Optimizers applied:\n"
            f"* Zero-Byte\n"
            f"* Early-Skip\n"
            f"* Optimized kernel\n\n"
            f"Status......: Cracked\n"
            f"Hash.Mode...: {hash_type} (MD5)\n"
            f"Hash.Target.: {hash_file}\n"
            f"Speed.#1....: 14234.5 MH/s\n\n"
            f"Recovered...: 3/5 (60.00%)\n"
            f"Progress....: 14,344,391/14,344,391 (100.00%)\n"
            f"Rejected....: 0/14,344,391 (0.00%)\n\n"
            f"Cracked hashes:\n"
            f"5f4dcc3b5aa765d61d8327deb882cf99:password\n"
            f"098f6bcd4621d373cade4e832627b4f6:test\n"
            f"25f9e794323b453885f5181f1b624d0b:123456\n\n"
            f"Session..........: hashcat\n"
            f"Status...........: Cracked\n"
            f"Started..........: 2026-04-09 12:00:00\n"
            f"Stopped..........: 2026-04-09 12:00:45"
        )
        return _build_result(True, command, output)

    if not os.path.exists(hash_file):
        return _build_result(False, command, "", f"Hash file not found: {hash_file}")
    if not os.path.exists(wordlist):
        return _build_result(False, command, "", f"Wordlist not found: {wordlist}. Try: gunzip /usr/share/wordlists/rockyou.txt.gz")

    stdout, stderr, code = _run_command(command, timeout=3600)
    success = code in (0, 1)  # 0=fully cracked, 1=exhausted/not all cracked
    return _build_result(success, command, stdout, stderr if code > 1 else "")


def john_crack(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    dry_run: bool = False
) -> dict:
    """
    Crack password hashes using John the Ripper.

    John automatically detects hash format and supports many formats including
    UNIX shadow, NTLM, MD5, SHA-1, and many more.

    Args:
        hash_file: Path to file containing hashes
        wordlist: Path to password wordlist file
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"john {hash_file} --wordlist={wordlist} --fork=4"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated John the Ripper cracking\n"
            f"Command: {command}\n\n"
            f"Using default input encoding: UTF-8\n"
            f"Loaded 5 password hashes with no different salts (raw-md5 [MD5 256/256 AVX2 8x3])\n"
            f"Will run 4 openMP threads\n"
            f"Press 'q' or Ctrl-C to abort, 'h' for help\n\n"
            f"password         (user1)\n"
            f"test             (user2)\n"
            f"123456           (admin)\n"
            f"letmein          (root)\n"
            f"3g 4:10:22:01 DONE (2026-04-09 12:00:00) 0p/s\n\n"
            f"Session completed. 4 cracked, 1 left uncracked.\n\n"
            f"Results:\n"
            f"user1:password\n"
            f"user2:test\n"
            f"admin:123456\n"
            f"root:letmein"
        )
        return _build_result(True, command, output)

    if not os.path.exists(hash_file):
        return _build_result(False, command, "", f"Hash file not found: {hash_file}")

    # Start cracking
    stdout, stderr, code = _run_command(command, timeout=3600)
    # Also show results
    show_stdout, _, _ = _run_command(f"john --show {hash_file}", timeout=30)
    full_output = f"{stdout}\n\nCracked passwords:\n{show_stdout}"
    success = code == 0
    return _build_result(success, command, full_output, stderr if not success else "")


def hydra_bruteforce(
    target: str,
    service: str,
    username: str,
    wordlist: str,
    dry_run: bool = False
) -> dict:
    """
    Brute force login credentials using Hydra.

    Supports: ssh, ftp, http-post-form, http-get, rdp, smb, telnet, mysql, postgresql, etc.

    Args:
        target: Target IP address or hostname
        service: Service to attack (e.g. ssh, ftp, http-post-form, rdp)
        username: Username to test, or path to username list (prefix with -L for list)
        wordlist: Path to password wordlist file
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    user_flag = f"-L {username}" if os.path.exists(username) else f"-l {username}"
    command = f"hydra -t 4 {user_flag} -P {wordlist} {target} {service} -o /tmp/hydra_results.txt"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Hydra brute force\n"
            f"Command: {command}\n\n"
            f"Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak\n\n"
            f"[WARNING] Many SSH configurations limit the number of parallel tasks.\n"
            f"[DATA] max 4 tasks per 1 server, overall 4 tasks\n"
            f"[DATA] attacking {service}://{target}:22/\n"
            f"[22][ssh] host: {target}   login: {username}   password: password123\n"
            f"[22][ssh] host: {target}   login: admin        password: admin\n"
            f"1 of 1 target successfully completed, 2 valid passwords found\n"
            f"Hydra (https://github.com/vanhauser-thc/thc-hydra) finished.\n"
            f"Results saved to: /tmp/hydra_results.txt"
        )
        return _build_result(True, command, output)

    if not os.path.exists(wordlist):
        return _build_result(False, command, "", f"Wordlist not found: {wordlist}")

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def medusa_bruteforce(
    target: str,
    service: str,
    username: str,
    wordlist: str,
    dry_run: bool = False
) -> dict:
    """
    Brute force login credentials using Medusa (parallel network login auditor).

    Args:
        target: Target IP address or hostname
        service: Module name (e.g. ssh, ftp, http, smb, rdp)
        username: Username to test
        wordlist: Path to password wordlist file
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"medusa -h {target} -u {username} -P {wordlist} -M {service} -t 4"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Medusa brute force\n"
            f"Command: {command}\n\n"
            f"Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks\n\n"
            f"ACCOUNT CHECK: [ssh] Host: {target} (1 of 1, 0 complete) User: {username} (1 of 1, 0 complete) Password: password (1 of 14344391 complete)\n"
            f"ACCOUNT FOUND: [ssh] Host: {target} User: {username} Password: password123 [SUCCESS]\n\n"
            f"Medusa finished: 1 success, 0 failures"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def crunch_generate(
    min_len: int,
    max_len: int,
    charset: str,
    output_file: str,
    dry_run: bool = False
) -> dict:
    """
    Generate custom wordlists using crunch based on character sets and length ranges.

    Args:
        min_len: Minimum password length
        max_len: Maximum password length
        charset: Character set string (e.g. 'abcdefghijklmnopqrstuvwxyz0123456789')
        output_file: Path to save generated wordlist
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"crunch {min_len} {max_len} {charset} -o {output_file}"

    if dry_run:
        charset_size = len(charset)
        total_words = sum(charset_size ** i for i in range(min_len, max_len + 1))
        output = (
            f"[DRY RUN] Simulated crunch wordlist generation\n"
            f"Command: {command}\n\n"
            f"Crunch will now generate the following amount of data:\n"
            f"  Charset: {charset}\n"
            f"  Min length: {min_len}\n"
            f"  Max length: {max_len}\n"
            f"  Estimated words: {total_words:,}\n\n"
            f"crunch 4.0 started with the following args:\n"
            f"{min_len} {max_len} {charset} -o {output_file}\n\n"
            f"crunch: 100% completed generating output\n"
            f"Wordlist saved to: {output_file}"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def cewl_generate(
    url: str,
    depth: int = 2,
    min_word_len: int = 4,
    dry_run: bool = False
) -> dict:
    """
    Generate a custom wordlist by spidering a website using CeWL.

    Crawls the target URL and extracts unique words to build a targeted wordlist.

    Args:
        url: Target URL to crawl for words
        depth: Spider depth (how many links deep to follow)
        min_word_len: Minimum word length to include
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    output_file = f"/tmp/cewl_{url.replace('http://', '').replace('https://', '').replace('/', '_')}.txt"
    command = f"cewl {url} -d {depth} -m {min_word_len} -w {output_file} --with-numbers"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated CeWL wordlist generation\n"
            f"Command: {command}\n\n"
            f"CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) <http://digi.ninja/>\n\n"
            f"Target: {url}\n"
            f"Spider depth: {depth}\n"
            f"Min word length: {min_word_len}\n\n"
            f"Words found:\n"
            f"password\n"
            f"admin\n"
            f"login\n"
            f"security\n"
            f"network\n"
            f"service\n"
            f"company\n"
            f"portal\n"
            f"corporate\n"
            f"internal\n\n"
            f"Total: 247 unique words extracted\n"
            f"Wordlist saved to: {output_file}"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=300)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def hashid_identify(hash_string: str, dry_run: bool = False) -> dict:
    """
    Identify the type of a hash string using hashid.

    Args:
        hash_string: The hash string to identify
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"hashid '{hash_string}'"

    if dry_run:
        hash_len = len(hash_string)
        guesses = {
            32: "MD5, MD4, MD2, Double MD5, LM, RIPEMD-128",
            40: "SHA-1, Double SHA-1, RIPEMD-160, Haval-160",
            56: "SHA-224, Haval-224",
            64: "SHA-256, RIPEMD-256, Haval-256, Snefru-256",
            96: "SHA-384, Haval-384",
            128: "SHA-512, Whirlpool, SHA-512(224), SHA-512(256)",
        }
        type_guess = guesses.get(hash_len, "Unknown hash type")
        output = (
            f"[DRY RUN] Simulated hash identification\n"
            f"Command: {command}\n\n"
            f"Analyzing: {hash_string}\n"
            f"Hash length: {hash_len} characters\n\n"
            f"Possible hash types:\n"
            f"  [+] {type_guess}\n\n"
            f"For hashcat, use:\n"
            f"  MD5: -m 0\n"
            f"  SHA-1: -m 100\n"
            f"  SHA-256: -m 1400\n"
            f"  NTLM: -m 1000\n"
            f"  sha512crypt: -m 1800"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=30)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")
