#!/usr/bin/env python3
"""
KaliGuard AI - Web Application Security Testing Tools Module

Wraps SQLMap, XSSer, FFUF, WFuzz, ZAP, Burp Suite, and Commix.

LEGAL: Authorized use only on web applications you own or have explicit written permission to test.
"""

import subprocess
import shlex
import os
import logging
from datetime import datetime

logger = logging.getLogger("kaliguard.tools.web")


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


def sqlmap_scan(
    url: str,
    params: str = "",
    level: int = 1,
    risk: int = 1,
    dry_run: bool = False
) -> dict:
    """
    Test a web URL for SQL injection vulnerabilities using SQLMap.

    Args:
        url: Target URL to test (e.g. http://192.168.1.100/login.php?id=1)
        params: POST data or specific parameter to test (e.g. 'user=test&pass=test')
        level: Test level 1-5 (higher = more thorough but slower)
        risk: Risk level 1-3 (higher = potentially more disruptive)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    data_flag = f"--data='{params}'" if params else ""
    command = f"sqlmap -u '{url}' {data_flag} --level={level} --risk={risk} --batch --random-agent --output-dir=/tmp/sqlmap"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated SQLMap scan\n"
            f"Command: {command}\n\n"
            f"        ___\n"
            f"       __H__\n"
            f" ___ ___[)]_____ ___ ___  {{1.7.10#stable}}\n"
            f"|_ -| . [,]     | .'| . |\n"
            f"|___|_  [']_|_|_|__,|  _|\n"
            f"      |_|V...       |_|   https://sqlmap.org\n\n"
            f"[*] starting @ 12:00:00\n\n"
            f"[12:00:01] [INFO] testing connection to the target URL\n"
            f"[12:00:02] [INFO] testing if the target URL content is stable\n"
            f"[12:00:03] [INFO] target URL content is stable\n"
            f"[12:00:04] [INFO] testing if GET parameter 'id' is dynamic\n"
            f"[12:00:05] [INFO] GET parameter 'id' appears to be dynamic\n"
            f"[12:00:06] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable\n"
            f"[12:00:10] [INFO] GET parameter 'id' is 'MySQL >= 5.0.12 AND time-based blind' injectable\n"
            f"[12:00:15] [INFO] GET parameter 'id' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable\n\n"
            f"sqlmap identified the following injection point(s) with a total of 45 HTTP(s) requests:\n"
            f"---\n"
            f"Parameter: id (GET)\n"
            f"    Type: time-based blind\n"
            f"    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)\n"
            f"    Payload: id=1 AND SLEEP(5)-- -\n\n"
            f"    Type: UNION query\n"
            f"    Title: MySQL UNION query (NULL) - 3 columns\n"
            f"    Payload: id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x71,...)\n"
            f"---\n\n"
            f"[12:00:20] [INFO] the back-end DBMS is MySQL\n"
            f"web server operating system: Linux Ubuntu\n"
            f"web application technology: Apache 2.4.52, PHP 7.4.3\n"
            f"back-end DBMS: MySQL >= 5.0.12\n\n"
            f"[!] SQL INJECTION FOUND: {url}\n"
            f"Parameter 'id' is vulnerable to time-based blind and UNION-based injection"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def xsser_scan(url: str, dry_run: bool = False) -> dict:
    """
    Test a web URL for Cross-Site Scripting (XSS) vulnerabilities using XSSer.

    Args:
        url: Target URL to test for XSS (e.g. http://192.168.1.100/search.php?q=test)
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"xsser --url '{url}' -a --auto"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated XSSer scan\n"
            f"Command: {command}\n\n"
            f"XSSer v1.8.4 - The Web Attacker Tool (https://xsser.03c8.net)\n\n"
            f"Testing: {url}\n\n"
            f"[*] Checking for Cross-Site Scripting in: {url}\n"
            f"[*] Trying to inject vector: <script>alert(1)</script>\n"
            f"[+] XSS FOUND! Injection vector: <script>alert(1)</script>\n"
            f"[+] XSS Parameter: q\n"
            f"[+] XSS Type: Reflected XSS\n"
            f"[+] XSS URL: {url}?q=<script>alert(1)</script>\n\n"
            f"Total XSS discovered: 1\n"
            f"[!] REFLECTED XSS vulnerability found in parameter 'q'"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=300)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def ffuf_fuzz(url: str, wordlist: str, dry_run: bool = False) -> dict:
    """
    Fuzz web application endpoints using FFUF (Fuzz Faster U Fool).

    Uses FUZZ keyword in URL, headers, or POST data as the injection point.

    Args:
        url: Target URL with FUZZ placeholder (e.g. http://192.168.1.100/FUZZ)
        wordlist: Path to wordlist file
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"ffuf -u '{url}' -w {wordlist} -mc 200,301,302,403 -t 50"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated FFUF fuzzing\n"
            f"Command: {command}\n\n"
            f"        /'___\\  /'___\\           /'___\\\n"
            f"       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/\n"
            f"       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\\n"
            f"        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/\n"
            f"         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\\n"
            f"          \\/_/    \\/_/   \\/___/    \\/_/\n\n"
            f"       v2.0.0-dev\n"
            f"________________________________________________\n\n"
            f" :: Method           : GET\n"
            f" :: URL              : {url}\n"
            f" :: Wordlist         : FUZZ: {wordlist}\n"
            f" :: Follow redirects : false\n"
            f" :: Threads          : 50\n\n"
            f"________________________________________________\n\n"
            f"admin                   [Status: 200, Size: 4521, Words: 234, Lines: 89]\n"
            f"login                   [Status: 200, Size: 2048, Words: 112, Lines: 45]\n"
            f"backup                  [Status: 403, Size: 277, Words: 21, Lines: 11]\n"
            f"config                  [Status: 403, Size: 277, Words: 21, Lines: 11]\n"
            f"phpMyAdmin              [Status: 200, Size: 8547, Words: 678, Lines: 210]\n"
            f"wp-admin                [Status: 301, Size: 0, Words: 0, Lines: 0]\n"
            f"upload                  [Status: 301, Size: 0, Words: 0, Lines: 0]\n\n"
            f":: Progress: [220560/220560] :: Job [1/1] :: 2145 req/sec :: Duration: [0:01:42] ::\n"
            f"7 results found."
        )
        return _build_result(True, command, output)

    if not os.path.exists(wordlist):
        return _build_result(False, command, "", f"Wordlist not found: {wordlist}")

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def wfuzz_fuzz(url: str, wordlist: str, dry_run: bool = False) -> dict:
    """
    Fuzz web application parameters and endpoints using WFuzz.

    Uses FUZZ keyword as the injection point in the URL.

    Args:
        url: Target URL with FUZZ placeholder
        wordlist: Path to wordlist file
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"wfuzz -c -w {wordlist} --hc 404 '{url}'"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated WFuzz fuzzing\n"
            f"Command: {command}\n\n"
            f"********************************************************\n"
            f"* Wfuzz 3.1.0 - The Web Fuzzer                        *\n"
            f"********************************************************\n\n"
            f"Target: {url}\n"
            f"Total requests: 220560\n\n"
            f"=====================================================================\n"
            f"ID           Response   Lines    Word       Chars       Payload\n"
            f"=====================================================================\n\n"
            f"000000001:   200        89 L     234 W      4521 Ch     \"admin\"\n"
            f"000000002:   200        45 L     112 W      2048 Ch     \"login\"\n"
            f"000000003:   403        11 L     21 W       277 Ch      \"backup\"\n"
            f"000000004:   403        11 L     21 W       277 Ch      \"config\"\n"
            f"000000005:   200        210 L    678 W      8547 Ch     \"phpMyAdmin\"\n\n"
            f"Total time: 102.34 seconds\n"
            f"Processed requests: 220560 | Filtered requests: 220555 | Requests/sec: 2156.23"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def zap_scan(target: str, dry_run: bool = False) -> dict:
    """
    Run OWASP ZAP automated security scanner against a web application.

    Requires OWASP ZAP to be installed. Uses the ZAP API for automated scanning.

    Args:
        target: Target URL for ZAP scan
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"zap-baseline.py -t {target} -r /tmp/zap_report.html"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated OWASP ZAP scan\n"
            f"Command: {command}\n\n"
            f"WARN-NEW: Anti-clickjacking Header [10020] x 1\n"
            f"  {target}\n\n"
            f"WARN-NEW: Content-Type Header Missing [10019] x 1\n"
            f"  {target}/api/\n\n"
            f"FAIL-NEW: SQL Injection [40018] x 1\n"
            f"  {target}/search.php\n\n"
            f"FAIL-NEW: Cross Site Scripting (Reflected) [40012] x 2\n"
            f"  {target}/search.php\n"
            f"  {target}/comment.php\n\n"
            f"FAIL-NEW: Directory Browsing [0] x 1\n"
            f"  {target}/uploads/\n\n"
            f"PASS: Cookie No HttpOnly Flag [10010]\n"
            f"PASS: Cookie Without Secure Flag [10011]\n\n"
            f"WARN-NEW: 2\tFAIL-NEW: 4\tFAIL-INPROG: 0\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 32\n\n"
            f"[!] CRITICAL: SQL Injection and XSS vulnerabilities found\n"
            f"Report saved to: /tmp/zap_report.html"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code in (0, 2)  # ZAP returns 2 for WARN, 0 for PASS
    return _build_result(success, command, stdout, stderr if code > 2 else "")


def burpsuite_scan(target: str, dry_run: bool = False) -> dict:
    """
    Run Burp Suite Community Edition headless crawler and scanner.

    Note: Full scanning requires Burp Suite Pro. Community edition is limited.
    Uses burpsuite-headless or the Burp Suite REST API.

    Args:
        target: Target URL for Burp Suite scan
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"java -jar /usr/share/burpsuite/burpsuite.jar --project-file=/tmp/burp_scan.burp --config-file=/tmp/burp_config.json"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Burp Suite scan\n"
            f"Target: {target}\n\n"
            f"NOTE: Full automated scanning requires Burp Suite Pro.\n"
            f"Community edition supports manual testing via proxy.\n\n"
            f"Burp Suite v2023.10.1 Starting...\n\n"
            f"[*] Starting spider for {target}\n"
            f"[*] Spider found 24 pages\n"
            f"[*] Starting active scanning...\n\n"
            f"Issues found:\n"
            f"  [HIGH] SQL injection - GET /search.php parameter 'q'\n"
            f"  [HIGH] Reflected XSS - GET /search.php parameter 'q'\n"
            f"  [MEDIUM] Directory listing - /uploads/ directory\n"
            f"  [MEDIUM] Missing CSRF token on login form\n"
            f"  [LOW] Verbose error messages exposing server info\n"
            f"  [INFO] Private IP disclosed in HTTP headers\n\n"
            f"Total: 6 issues found\n"
            f"Report saved to: /tmp/burp_report.html\n"
            f"\nAlternative: Use OWASP ZAP for free automated scanning:\n"
            f"  kaliguard chat -> 'Run ZAP scan on {target}'"
        )
        return _build_result(True, command, output)

    # Check if Burp Suite is installed
    burp_paths = [
        "/usr/share/burpsuite/burpsuite.jar",
        "/opt/burpsuite/burpsuite.jar",
        "/usr/bin/burpsuite"
    ]
    burp_found = any(os.path.exists(p) for p in burp_paths)
    if not burp_found:
        return _build_result(False, command, "",
                             "Burp Suite not found. Install with: sudo apt install burpsuite\n"
                             "Or use ZAP for free scanning: zap-baseline.py -t " + target)

    stdout, stderr, code = _run_command(command, timeout=600)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")


def commix_scan(url: str, dry_run: bool = False) -> dict:
    """
    Test for command injection vulnerabilities using Commix.

    Args:
        url: Target URL to test for OS command injection
        dry_run: If True, simulate execution

    Returns:
        dict with keys: success, command, output, error, timestamp
    """
    command = f"commix --url='{url}' --batch --output-dir=/tmp/commix"

    if dry_run:
        output = (
            f"[DRY RUN] Simulated Commix command injection scan\n"
            f"Command: {command}\n\n"
            f"Commix - Automated All-in-One OS Command Injection and Exploitation Tool\n"
            f"Copyright (c) 2014-2023 Anastasios Stasinopoulos\n\n"
            f"[*] Testing connection to the target URL.\n"
            f"[*] Checking if the target is accessible.\n"
            f"[*] Setting the POST parameter 'cmd' for tests.\n\n"
            f"[+] The POST parameter 'cmd' seems injectable via results-based command injection techniques.\n"
            f"[+] Type: results-based (classic)\n"
            f"[+] Payload: cmd=id;echo XXXXXXXXXXXXXXX\n\n"
            f"[!] COMMAND INJECTION FOUND!\n"
            f"Injection point: POST parameter 'cmd'\n"
            f"Technique: Classic command injection\n\n"
            f"Shell> id\n"
            f"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n\n"
            f"[!] Remote code execution confirmed via command injection"
        )
        return _build_result(True, command, output)

    stdout, stderr, code = _run_command(command, timeout=300)
    success = code == 0
    return _build_result(success, command, stdout, stderr if not success else "")
