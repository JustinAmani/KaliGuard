#!/usr/bin/env python3
"""
KaliGuard AI - Cryptography & Steganography Analysis Tools Module

Wraps openssl, steghide, stegseek, exiftool, hashid, gpg, and zsteg.

LEGAL: Authorized use only on files you own or have explicit written permission to analyze.
"""

import subprocess
import shlex
import os
import logging
from datetime import datetime

logger = logging.getLogger("kaliguard.tools.crypto")


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


def openssl_analyze(file_path: str = None, operation: str = "info", dry_run: bool = False) -> dict:
    """
    Analyze SSL/TLS certificates or perform cryptographic operations with OpenSSL.

    Operations:
    - info: Display certificate information
    - verify: Verify certificate validity
    - ciphers: List supported cipher suites
    - s_client: Test SSL/TLS connection (file_path should be host:port)

    Args:
        file_path: Path to certificate file or host:port for TLS testing
        operation: Operation to perform (info, verify, ciphers, s_client)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    if operation == "ciphers":
        command = "openssl ciphers -v 'ALL:eNULL'"
    elif operation == "s_client" and file_path:
        command = f"echo | openssl s_client -connect {file_path} -showcerts"
    elif file_path and os.path.exists(file_path):
        command = f"openssl x509 -in {file_path} -text -noout"
    else:
        command = f"openssl version"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated OpenSSL analysis\n"
            f"Command: {command}\n\n"
            f"Certificate Information:\n"
            f"  Version: 3 (0x2)\n"
            f"  Serial Number: 04:00:00:00:00:01:15:4b:5a:c3:94\n"
            f"  Signature Algorithm: sha256WithRSAEncryption\n"
            f"  Issuer: C=BE, O=GlobalSign nv-sa, CN=GlobalSign Root CA\n"
            f"  Validity:\n"
            f"    Not Before: Jan 15 12:00:00 2024 GMT\n"
            f"    Not After : Jan 15 12:00:00 2026 GMT\n"
            f"  Subject: CN=example.com\n"
            f"  Subject Alternative Names:\n"
            f"    DNS:example.com\n"
            f"    DNS:www.example.com\n"
            f"  Public Key Algorithm: rsaEncryption\n"
            f"  RSA Public-Key: (2048 bit)\n"
            f"  Signature Algorithm: sha256WithRSAEncryption\n\n"
            f"Security Assessment:\n"
            f"  [OK] Certificate is valid\n"
            f"  [OK] 2048-bit RSA key (minimum recommended)\n"
            f"  [WARN] Expires in 245 days - plan for renewal\n"
            f"  [OK] SHA-256 signature algorithm\n"
            f"  [WARN] TLS 1.0 and 1.1 may be supported (check server config)"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=30)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def steghide_extract(image_file: str, passphrase: str = "", dry_run: bool = False) -> dict:
    """
    Attempt to extract hidden data from an image using steghide.

    Steghide hides data inside JPEG, BMP, WAV, and AU files.

    Args:
        image_file: Path to image file to check for hidden data
        passphrase: Passphrase to try for extraction (empty string for no passphrase)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    output_file = f"/tmp/steghide_extracted_{os.path.basename(image_file)}.txt"
    command = f"steghide extract -sf {image_file} -p '{passphrase}' -f -xf {output_file}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated steghide extraction\n"
            f"Command: {command}\n\n"
            f"steghide: version 0.5.1\n\n"
            f"Reading {image_file}...\n"
            f"Extracting secret message...\n\n"
            f"[+] Extraction successful!\n"
            f"Hidden data extracted to: {output_file}\n\n"
            f"Content of hidden data:\n"
            f"-----BEGIN HIDDEN MESSAGE-----\n"
            f"Secret credentials:\n"
            f"  username: admin\n"
            f"  password: S3cr3tP@ssw0rd!\n"
            f"  server: 192.168.1.100\n"
            f"-----END HIDDEN MESSAGE-----\n\n"
            f"[!] Steganography detected: Credentials hidden in image file"
        )
        return _build_result(True, command, output)

    if not os.path.exists(image_file):
        return _build_result(False, command, "", f"Image file not found: {image_file}")

    stdout, stderr, code = _run_command(command, timeout=60)
    if code == 0 and os.path.exists(output_file):
        with open(output_file, 'r', errors='replace') as f:
            extracted = f.read()
        output = f"Extraction successful!\nContent:\n{extracted}"
    else:
        output = stdout
    success = code == 0
    return _build_result(success, command, output, stderr if not success else "")


def stegseek_crack(image_file: str, wordlist: str, dry_run: bool = False) -> dict:
    """
    Crack steghide-protected files using stegseek wordlist attack.

    Stegseek is much faster than steghide for brute forcing passphrases.

    Args:
        image_file: Path to image file to crack
        wordlist: Path to wordlist for passphrase cracking
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"stegseek {image_file} {wordlist}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated stegseek cracking\n"
            f"Command: {command}\n\n"
            f"StegSeek 0.6 - https://github.com/RickdeJager/stegseek\n\n"
            f"[i] Found passphrase: \"password123\"\n"
            f"[i] Original filename: \"secret.txt\"\n"
            f"[i] Extracting to \"{image_file}.out\"\n\n"
            f"Content of hidden file:\n"
            f"This is the secret message hidden in the image.\n"
            f"Credentials: admin:P@ssw0rd!\n\n"
            f"[!] Passphrase cracked: 'password123'\n"
            f"[!] Steganography confirmed with weak passphrase"
        )
        return _build_result(True, command, output)

    if not os.path.exists(image_file):
        return _build_result(False, command, "", f"Image file not found: {image_file}")
    if not os.path.exists(wordlist):
        return _build_result(False, command, "", f"Wordlist not found: {wordlist}")

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def exiftool_analyze(file_path: str, dry_run: bool = False) -> dict:
    """
    Extract and analyze metadata from files using ExifTool.

    Supports images (JPEG, PNG, TIFF), documents (PDF, DOCX), audio/video, and more.

    Args:
        file_path: Path to file to extract metadata from
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"exiftool {file_path}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated ExifTool metadata extraction\n"
            f"Command: {command}\n\n"
            f"ExifTool Version Number         : 12.60\n"
            f"File Name                       : {os.path.basename(file_path)}\n"
            f"File Size                       : 1.2 MB\n"
            f"File Type                       : JPEG\n"
            f"MIME Type                       : image/jpeg\n"
            f"Image Width                     : 3840\n"
            f"Image Height                    : 2160\n"
            f"Bits Per Sample                 : 8\n"
            f"Camera Model Name               : iPhone 14 Pro\n"
            f"Software                        : 16.0\n"
            f"Modify Date                     : 2025:12:15 14:32:01\n"
            f"Create Date                     : 2025:12:15 14:32:01\n"
            f"GPS Latitude                    : 20 deg 9' 0.12\" S [LOCATION DATA FOUND]\n"
            f"GPS Longitude                   : 57 deg 30' 21.36\" E [LOCATION DATA FOUND]\n"
            f"GPS Altitude                    : 15.3 m\n"
            f"GPS Speed                       : 0\n"
            f"Author                          : John Doe\n"
            f"Creator Tool                    : Adobe Photoshop CC 2024\n\n"
            f"[!] GPS location data embedded: -20.150, 57.506 (Mauritius)\n"
            f"[!] Author identity exposed: John Doe"
        )
        return _build_result(True, command, output)

    if not os.path.exists(file_path):
        return _build_result(False, command, "", f"File not found: {file_path}")

    stdout, stderr, code = _run_command(command, timeout=30)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def hashid_identify(hash_string: str, dry_run: bool = False) -> dict:
    """
    Identify the type of a hash using hashid.

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
            32: ["MD5 (-m 0)", "MD4 (-m 900)", "NTLM (-m 1000)", "Domain Cached Credentials (-m 1100)"],
            40: ["SHA-1 (-m 100)", "MySQL 4.1 (-m 300)", "RIPEMD-160 (-m 6000)"],
            64: ["SHA-256 (-m 1400)", "RIPEMD-256", "Haval-256", "Snefru-256"],
            128: ["SHA-512 (-m 1700)", "Whirlpool (-m 6100)", "SHA-512 (224)", "SHA-512 (256)"],
        }
        type_list = guesses.get(hash_len, ["Unknown type"])
        output = (
            f"[DRY RUN] Simulated hashid identification\n"
            f"Command: {command}\n\n"
            f"Analyzing: {hash_string[:32]}{'...' if len(hash_string) > 32 else ''}\n"
            f"Hash length: {hash_len} characters\n\n"
            f"Possible algorithms:\n"
        )
        for t in type_list:
            output += f"  [+] {t}\n"
        output += f"\nFor online lookup: https://hashes.com/en/tools/hash_identifier"
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=30)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def gpg_analyze(file_path: str, dry_run: bool = False) -> dict:
    """
    Analyze a GPG-encrypted or signed file using gpg.

    Args:
        file_path: Path to GPG file to analyze
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"gpg --list-packets {file_path}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated GPG analysis\n"
            f"Command: {command}\n\n"
            f"gpg: processing {file_path}\n\n"
            f":public key encrypted packet:\n"
            f"\tversion 3, algo 16, keyid E11B38F0F32A8123\n"
            f"\tdata: [2048 bits]\n"
            f"\tdata: [2048 bits]\n\n"
            f":encrypted data packet:\n"
            f"\tlength: 1234\n"
            f"\tencrypt: algo 9 (AES256)\n\n"
            f"File type: PGP symmetric encrypted data (AES-256)\n"
            f"Signed by key: E11B38F0F32A8123\n\n"
            f"To decrypt: gpg --decrypt {file_path}\n"
            f"To verify signature: gpg --verify {file_path}"
        )
        return _build_result(True, command, output)

    if not os.path.exists(file_path):
        return _build_result(False, command, "", f"File not found: {file_path}")

    stdout, stderr, code = _run_command(command, timeout=30)
    success = code == 0
    return _build_result(success, command, stdout or stderr)


def zsteg_analyze(image_file: str, dry_run: bool = False) -> dict:
    """
    Analyze a PNG or BMP image for hidden data using zsteg.

    Zsteg detects LSB steganography, zlib-compressed data, and other hidden content.

    Args:
        image_file: Path to PNG or BMP image file
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"zsteg -a {image_file}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated zsteg analysis\n"
            f"Command: {command}\n\n"
            f"[.] checking zcmdpng 'pHYs'\n"
            f"[.] checking zcmdpng 'cHRM'\n"
            f"[.] checking zcmdpng 'zCom'\n\n"
            f"imagedata           .. text: \"\\n\\t\\t\\t\"\n"
            f"b1,r,lsb,xy         .. text: \"iCENDIF\"\n"
            f"b1,rgb,lsb,xy       .. text: \"Secret hidden message: flag{{steg0_1s_fun}}\"\n"
            f"b1,rgba,lsb,xy      .. text: \"password: SuperSecret123\"\n"
            f"b2,r,lsb,xy         .. file: JPEG image data\n"
            f"b4,r,lsb,xy         .. file: gzip compressed data\n\n"
            f"[!] Hidden text found in LSB of RGB channels:\n"
            f"  - 'Secret hidden message: flag{{steg0_1s_fun}}'\n"
            f"  - 'password: SuperSecret123'\n"
            f"[!] Embedded JPEG image found in red channel LSB\n"
            f"[!] Embedded gzip archive found in 4-bit red channel"
        )
        return _build_result(True, command, output)

    if not os.path.exists(image_file):
        return _build_result(False, command, "", f"Image file not found: {image_file}")

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")
