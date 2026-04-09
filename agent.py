#!/usr/bin/env python3
"""
KaliGuard AI Agent - Core AI engine using Anthropic Claude with tool_use.

This module defines the KaliGuardAgent class which orchestrates all security
tool calls via Claude's function calling (tool_use) API.

LEGAL: Authorized use only on networks/systems you own or have explicit written permission to test.
"""

import os
import json
import yaml
import sqlite3
import logging
import ipaddress
from datetime import datetime
from typing import Optional, List, Dict, Any

import anthropic
from rich.console import Console

# Import all tool modules
from tools import reconnaissance, vulnerability, forensics, network, cracking, wireless, web, reverse_eng, crypto, anonymity, reporting

console = Console()
logger = logging.getLogger("kaliguard.agent")


SYSTEM_PROMPT = """You are KaliGuard AI, an expert defensive cybersecurity agent.
You assist security professionals with authorized penetration testing, vulnerability assessment,
forensic analysis, and network security monitoring on their own networks.

IMPORTANT RULES:
1. Only operate on targets that are within allowed networks (private IP ranges by default).
2. Always explain what you are doing before executing any tool.
3. After each tool result, analyze the output and provide actionable security insights.
4. If a target appears to be a public IP or outside allowed networks, refuse and explain why.
5. Save important findings using save_finding tool.
6. Recommend remediation steps for every vulnerability found.
7. You have access to Kali Linux tools via function calls.

When analyzing results:
- Classify findings by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Provide CVSS-style risk assessment when relevant
- Always suggest concrete remediation steps
- Document findings for the security report

You are a defender. Your goal is to help organizations improve their security posture."""


# ============================================================
# TOOL DEFINITIONS FOR CLAUDE
# ============================================================

TOOLS = [
    {
        "name": "nmap_scan",
        "description": "Run an Nmap network scan against a target IP or range. Returns open ports, services, and OS detection results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address, hostname, or CIDR range to scan (e.g. 192.168.1.1 or 192.168.1.0/24)"
                },
                "ports": {
                    "type": "string",
                    "description": "Port range to scan (e.g. '1-1000', '80,443,8080', '1-65535')",
                    "default": "1-1000"
                },
                "scan_type": {
                    "type": "string",
                    "description": "Nmap scan type: SYN, TCP, UDP, ACK, FIN, XMAS, NULL, PING",
                    "enum": ["SYN", "TCP", "UDP", "ACK", "FIN", "XMAS", "NULL", "PING"],
                    "default": "SYN"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "nikto_scan",
        "description": "Run Nikto web vulnerability scanner against a web server target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or IP (e.g. http://192.168.1.100 or 192.168.1.100)"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "gobuster_scan",
        "description": "Run Gobuster directory/file brute forcing against a web target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL (e.g. http://192.168.1.100)"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file",
                    "default": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "openvas_scan",
        "description": "Run OpenVAS vulnerability scanner against a target for comprehensive vulnerability detection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address or hostname"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "searchsploit_search",
        "description": "Search the Exploit-DB database for known exploits related to a service or software.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query (e.g. 'Apache 2.4', 'OpenSSH 7.2', 'WordPress 5.8')"
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "wireshark_capture",
        "description": "Capture network packets using tshark (Wireshark CLI) on a specified interface.",
        "input_schema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Network interface to capture on (e.g. eth0, wlan0)",
                    "default": "eth0"
                },
                "duration": {
                    "type": "integer",
                    "description": "Capture duration in seconds",
                    "default": 60
                },
                "filter": {
                    "type": "string",
                    "description": "BPF capture filter expression (e.g. 'tcp port 80', 'host 192.168.1.1')",
                    "default": ""
                }
            },
            "required": ["interface"]
        }
    },
    {
        "name": "tcpdump_capture",
        "description": "Capture network packets using tcpdump on a specified interface.",
        "input_schema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Network interface to capture on (e.g. eth0, wlan0)",
                    "default": "eth0"
                },
                "duration": {
                    "type": "integer",
                    "description": "Capture duration in seconds",
                    "default": 60
                },
                "filter": {
                    "type": "string",
                    "description": "BPF filter expression",
                    "default": ""
                }
            },
            "required": ["interface"]
        }
    },
    {
        "name": "volatility_analyze",
        "description": "Analyze a memory dump using Volatility3 forensic framework.",
        "input_schema": {
            "type": "object",
            "properties": {
                "memory_file": {
                    "type": "string",
                    "description": "Path to the memory dump file"
                },
                "plugin": {
                    "type": "string",
                    "description": "Volatility plugin to run (e.g. pslist, pstree, netscan, malfind, dumpfiles)",
                    "default": "pslist"
                }
            },
            "required": ["memory_file"]
        }
    },
    {
        "name": "hashcat_crack",
        "description": "Attempt to crack password hashes using Hashcat GPU-accelerated cracking.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hash_file": {
                    "type": "string",
                    "description": "Path to file containing hashes to crack"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file",
                    "default": "/usr/share/wordlists/rockyou.txt"
                },
                "hash_type": {
                    "type": "string",
                    "description": "Hashcat hash type code (e.g. '0' for MD5, '100' for SHA1, '1000' for NTLM)",
                    "default": "0"
                }
            },
            "required": ["hash_file"]
        }
    },
    {
        "name": "john_crack",
        "description": "Crack password hashes using John the Ripper.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hash_file": {
                    "type": "string",
                    "description": "Path to file containing hashes to crack"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file",
                    "default": "/usr/share/wordlists/rockyou.txt"
                }
            },
            "required": ["hash_file"]
        }
    },
    {
        "name": "hydra_bruteforce",
        "description": "Brute force login credentials using Hydra against a target service.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address or hostname"
                },
                "service": {
                    "type": "string",
                    "description": "Service to attack (e.g. ssh, ftp, http-post-form, rdp, smb)"
                },
                "username": {
                    "type": "string",
                    "description": "Username or path to username list"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to password wordlist"
                }
            },
            "required": ["target", "service", "username", "wordlist"]
        }
    },
    {
        "name": "aircrack_scan",
        "description": "Scan for wireless networks and analyze WPA/WEP security using aircrack-ng suite.",
        "input_schema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Wireless interface in monitor mode (e.g. wlan0mon)"
                }
            },
            "required": ["interface"]
        }
    },
    {
        "name": "sqlmap_scan",
        "description": "Test a web URL for SQL injection vulnerabilities using SQLMap.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to test for SQL injection"
                },
                "params": {
                    "type": "string",
                    "description": "POST parameters or specific parameter to test",
                    "default": ""
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "burpsuite_scan",
        "description": "Run Burp Suite headless scan against a web target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL for Burp Suite scan"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "yara_scan",
        "description": "Scan a file or directory with YARA rules for malware detection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to file or directory to scan"
                },
                "rules": {
                    "type": "string",
                    "description": "Path to YARA rules file or directory",
                    "default": "/usr/share/yara-rules/"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "generate_report",
        "description": "Generate a security report (PDF or HTML) for a session's findings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID to generate report for"
                },
                "format": {
                    "type": "string",
                    "description": "Report format: pdf or html",
                    "enum": ["pdf", "html"],
                    "default": "pdf"
                }
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "save_finding",
        "description": "Save a security finding to the database for inclusion in reports.",
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Finding category (e.g. 'Open Port', 'SQL Injection', 'Weak Password', 'Malware')"
                },
                "severity": {
                    "type": "string",
                    "description": "Severity level",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the finding including evidence and impact"
                },
                "target": {
                    "type": "string",
                    "description": "Target IP, URL, or file where finding was discovered"
                }
            },
            "required": ["category", "severity", "description", "target"]
        }
    },
    {
        "name": "get_session_findings",
        "description": "Retrieve all security findings saved for a specific session from the database.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID to retrieve findings for"
                }
            },
            "required": ["session_id"]
        }
    },
]


class KaliGuardAgent:
    """
    Core KaliGuard AI agent that orchestrates security tools via Claude AI.

    Uses Claude's tool_use feature to intelligently select and execute
    Kali Linux security tools based on natural language instructions.
    """

    def __init__(self, config: dict, dry_run: bool = False):
        """
        Initialize the KaliGuard agent.

        Args:
            config: Loaded configuration dictionary from config.yaml
            dry_run: If True, simulate tool execution without running real commands
        """
        self.config = config
        self.dry_run = dry_run or config.get("security", {}).get("dry_run", False)
        self.model = config.get("ai", {}).get("model", "claude-opus-4-6")
        self.max_tokens = config.get("ai", {}).get("max_tokens", 4096)

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable not set. "
                "Export it with: export ANTHROPIC_API_KEY='your-key-here'"
            )
        self.client = anthropic.Anthropic(api_key=api_key)

        self.db_path = config.get("database", {}).get("sessions_db", "database/sessions.db")
        self._init_database()

        self.allowed_networks = [
            ipaddress.ip_network(net, strict=False)
            for net in config.get("security", {}).get("allowed_networks", [
                "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"
            ])
        ]

        logger.info(f"KaliGuardAgent initialized. Model: {self.model}, Dry run: {self.dry_run}")

    def _init_database(self):
        """Initialize the sessions database if it doesn't exist."""
        import os
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                status TEXT DEFAULT 'active'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        conn.commit()
        conn.close()

    def _is_safe_target(self, target: str) -> bool:
        """
        Validate that target IP is within allowed network ranges.

        Args:
            target: IP address, hostname, or CIDR range string

        Returns:
            True if target is safe to scan, False otherwise
        """
        import re
        # Extract IP from URLs or CIDR
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', target)
        if not ip_match:
            # Hostname - allow with warning (could resolve to private IP)
            logger.warning(f"Target {target} is a hostname, cannot validate IP range")
            return True

        ip_str = ip_match.group(1)
        try:
            target_ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        # Allow loopback
        if target_ip.is_loopback:
            return True

        for allowed_net in self.allowed_networks:
            if target_ip in allowed_net:
                return True

        return False

    def run_tool(self, tool_name: str, tool_input: dict, session_id: str = None) -> str:
        """
        Dispatch a tool call to the appropriate module function.

        Args:
            tool_name: Name of the tool to run
            tool_input: Dictionary of input parameters
            session_id: Current session ID for context

        Returns:
            JSON string with tool execution results
        """
        dry_run = self.dry_run
        result = None

        try:
            if tool_name == "nmap_scan":
                target = tool_input.get("target")
                if not self._is_safe_target(target):
                    return json.dumps({"success": False, "error": f"Target {target} is outside allowed networks. Aborting for security."})
                result = reconnaissance.nmap_scan(
                    target=target,
                    ports=tool_input.get("ports", "1-1000"),
                    scan_type=tool_input.get("scan_type", "SYN"),
                    dry_run=dry_run
                )

            elif tool_name == "nikto_scan":
                target = tool_input.get("target")
                result = reconnaissance.nikto_scan(target=target, dry_run=dry_run)

            elif tool_name == "gobuster_scan":
                result = reconnaissance.gobuster_scan(
                    target=tool_input.get("target"),
                    wordlist=tool_input.get("wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
                    dry_run=dry_run
                )

            elif tool_name == "openvas_scan":
                target = tool_input.get("target")
                if not self._is_safe_target(target):
                    return json.dumps({"success": False, "error": f"Target {target} is outside allowed networks."})
                result = vulnerability.openvas_scan(target=target, dry_run=dry_run)

            elif tool_name == "searchsploit_search":
                result = vulnerability.searchsploit_search(
                    query=tool_input.get("query"),
                    dry_run=dry_run
                )

            elif tool_name == "wireshark_capture":
                result = network.tshark_capture(
                    interface=tool_input.get("interface", "eth0"),
                    duration=tool_input.get("duration", 60),
                    filter_expr=tool_input.get("filter", ""),
                    dry_run=dry_run
                )

            elif tool_name == "tcpdump_capture":
                result = network.tcpdump_capture(
                    interface=tool_input.get("interface", "eth0"),
                    duration=tool_input.get("duration", 60),
                    filter_expr=tool_input.get("filter", ""),
                    dry_run=dry_run
                )

            elif tool_name == "volatility_analyze":
                result = forensics.volatility_analyze(
                    memory_file=tool_input.get("memory_file"),
                    plugin=tool_input.get("plugin", "pslist"),
                    dry_run=dry_run
                )

            elif tool_name == "hashcat_crack":
                result = cracking.hashcat_crack(
                    hash_file=tool_input.get("hash_file"),
                    wordlist=tool_input.get("wordlist", "/usr/share/wordlists/rockyou.txt"),
                    hash_type=tool_input.get("hash_type", "0"),
                    dry_run=dry_run
                )

            elif tool_name == "john_crack":
                result = cracking.john_crack(
                    hash_file=tool_input.get("hash_file"),
                    wordlist=tool_input.get("wordlist", "/usr/share/wordlists/rockyou.txt"),
                    dry_run=dry_run
                )

            elif tool_name == "hydra_bruteforce":
                target = tool_input.get("target")
                if not self._is_safe_target(target):
                    return json.dumps({"success": False, "error": f"Target {target} is outside allowed networks."})
                result = cracking.hydra_bruteforce(
                    target=target,
                    service=tool_input.get("service"),
                    username=tool_input.get("username"),
                    wordlist=tool_input.get("wordlist"),
                    dry_run=dry_run
                )

            elif tool_name == "aircrack_scan":
                result = wireless.airodump_scan(
                    interface=tool_input.get("interface"),
                    dry_run=dry_run
                )

            elif tool_name == "sqlmap_scan":
                result = web.sqlmap_scan(
                    url=tool_input.get("url"),
                    params=tool_input.get("params", ""),
                    dry_run=dry_run
                )

            elif tool_name == "burpsuite_scan":
                result = web.burpsuite_scan(
                    target=tool_input.get("target"),
                    dry_run=dry_run
                )

            elif tool_name == "yara_scan":
                result = forensics.yara_scan(
                    file_path=tool_input.get("file_path"),
                    rules_path=tool_input.get("rules", "/usr/share/yara-rules/"),
                    dry_run=dry_run
                )

            elif tool_name == "generate_report":
                sid = tool_input.get("session_id", session_id)
                findings = reporting.get_session_findings(self.db_path, sid)
                fmt = tool_input.get("format", "pdf")
                output_dir = self.config.get("reports", {}).get("output_dir", "reports/")
                if fmt == "pdf":
                    result = reporting.generate_pdf_report(sid, findings, output_dir=output_dir)
                else:
                    result = reporting.generate_html_report(sid, findings, output_dir=output_dir)

            elif tool_name == "save_finding":
                sid = session_id or "unknown"
                result = reporting.save_finding_to_db(
                    db_path=self.db_path,
                    session_id=sid,
                    category=tool_input.get("category"),
                    severity=tool_input.get("severity"),
                    description=tool_input.get("description"),
                    target=tool_input.get("target")
                )

            elif tool_name == "get_session_findings":
                sid = tool_input.get("session_id", session_id)
                findings = reporting.get_session_findings(self.db_path, sid)
                result = {"success": True, "findings": findings, "count": len(findings)}

            else:
                result = {"success": False, "error": f"Unknown tool: {tool_name}"}

        except Exception as e:
            logger.error(f"Tool execution error [{tool_name}]: {e}", exc_info=True)
            result = {"success": False, "error": str(e), "tool": tool_name}

        return json.dumps(result, default=str)

    def chat(self, user_message: str, session_id: str = None, history: list = None) -> str:
        """
        Send a message to Claude AI and handle tool_use responses.

        Args:
            user_message: The user's natural language request
            session_id: Current session ID for database operations
            history: Previous conversation history (list of dicts with role/content)

        Returns:
            Claude's final text response after executing any required tools
        """
        if not session_id:
            session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        self._ensure_session(session_id)

        messages = []
        if history:
            for entry in history:
                messages.append({
                    "role": entry["role"],
                    "content": entry["content"]
                })
        messages.append({"role": "user", "content": user_message})

        max_iterations = 15
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=SYSTEM_PROMPT,
                    tools=TOOLS,
                    messages=messages
                )
            except anthropic.APIError as e:
                logger.error(f"Anthropic API error: {e}")
                return f"AI API error: {e}"

            if response.stop_reason == "end_turn":
                # Extract final text response
                for block in response.content:
                    if hasattr(block, "text"):
                        return block.text
                return "Analysis complete. No additional output."

            if response.stop_reason == "tool_use":
                messages.append({"role": "assistant", "content": response.content})

                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        tool_name = block.name
                        tool_input = block.input

                        console.print(f"  [bold yellow]>[/bold yellow] Executing [cyan]{tool_name}[/cyan]...", end="")

                        tool_output = self.run_tool(tool_name, tool_input, session_id=session_id)

                        try:
                            output_data = json.loads(tool_output)
                            success = output_data.get("success", True)
                            status_icon = "[green]done[/green]" if success else "[red]failed[/red]"
                        except Exception:
                            status_icon = "[green]done[/green]"

                        console.print(f" {status_icon}")

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": tool_output
                        })

                messages.append({"role": "user", "content": tool_results})
            else:
                # Unexpected stop reason
                for block in response.content:
                    if hasattr(block, "text"):
                        return block.text
                return f"Unexpected stop reason: {response.stop_reason}"

        return "Maximum tool iteration limit reached. Analysis may be incomplete."

    def _ensure_session(self, session_id: str):
        """Create session record in database if it doesn't exist."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO sessions (id, created_at) VALUES (?, ?)",
                (session_id, datetime.now().isoformat())
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Could not ensure session {session_id}: {e}")

    def process_workflow(self, workflow_name: str, target: str = None, session_id: str = None) -> str:
        """
        Run a predefined workflow (sequence of tools).

        Args:
            workflow_name: Name of workflow from config (e.g. 'quick_recon', 'full_audit')
            target: Target for the workflow
            session_id: Session ID for this workflow run

        Returns:
            Final AI analysis result
        """
        workflows = self.config.get("workflows", {})
        if workflow_name not in workflows:
            available = ", ".join(workflows.keys())
            return f"Unknown workflow '{workflow_name}'. Available: {available}"

        steps = workflows[workflow_name]

        if not session_id:
            session_id = f"{workflow_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        target_str = f" against target {target}" if target else ""
        prompt = (
            f"Execute the {workflow_name} security workflow{target_str}. "
            f"Run these tools in sequence: {', '.join(steps)}. "
            f"After each tool, analyze results and identify security issues. "
            f"Save all findings to the database. "
            f"Provide a comprehensive summary at the end. "
            f"Session ID: {session_id}"
        )

        return self.chat(prompt, session_id=session_id)
