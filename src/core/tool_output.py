#!/usr/bin/env python3
"""
Standardized Tool Output Format for FORGE V2.

All FORGE-generated tools should output results in this JSON format
so the Target Model can parse them deterministically.

Format:
{
    "tool": "ssh_connect_stdlib",
    "status": "success" | "failed",
    "target": "10.10.10.103",
    "findings": {
        "credentials": [{"user": "x", "pass": "y", "source": "z"}],
        "ssh_keys": [{"path": "/...", "encrypted": false}],
        "services": [{"port": 22, "proto": "ssh", "banner": "..."}],
        "vulnerabilities": [{"type": "sqli", "location": "/login.php"}],
        "files": ["/etc/shadow", "/home/user/.aws/credentials"],
        "lateral_targets": ["10.10.10.103", "10.10.10.104"],
        "access_level": "user" | "root" | null,
        "hostname": "web01",
    },
    "raw_output": "... original tool output ..."
}

Tools that don't use this format will still work — the Target Model
has regex-based fallback parsing. But JSON output is preferred.
"""

import json
import sys
from typing import Dict, List, Optional


class ToolOutput:
    """Helper class for FORGE tools to produce standardized output."""

    def __init__(self, tool_name: str, target: str = ""):
        self.tool_name = tool_name
        self.target = target
        self.status = "success"
        self.findings = {
            "credentials": [],
            "ssh_keys": [],
            "services": [],
            "vulnerabilities": [],
            "files": [],
            "lateral_targets": [],
            "access_level": None,
            "hostname": None,
        }
        self.raw_lines = []

    def add_credential(self, user: str, password: str, source: str = ""):
        self.findings["credentials"].append(
            {"user": user, "pass": password, "source": source}
        )

    def add_ssh_key(self, path: str, encrypted: bool = False):
        self.findings["ssh_keys"].append(
            {"path": path, "encrypted": encrypted}
        )

    def add_service(self, port: int, proto: str, banner: str = ""):
        self.findings["services"].append(
            {"port": port, "proto": proto, "banner": banner}
        )

    def add_vulnerability(self, vuln_type: str, location: str = ""):
        self.findings["vulnerabilities"].append(
            {"type": vuln_type, "location": location}
        )

    def add_file(self, path: str):
        self.findings["files"].append(path)

    def add_lateral_target(self, ip: str):
        if ip not in self.findings["lateral_targets"]:
            self.findings["lateral_targets"].append(ip)

    def set_access(self, level: str):
        self.findings["access_level"] = level

    def set_hostname(self, hostname: str):
        self.findings["hostname"] = hostname

    def log(self, message: str):
        """Add a human-readable log line (also printed to stdout)."""
        self.raw_lines.append(message)
        print(message)

    def fail(self, reason: str):
        self.status = "failed"
        self.raw_lines.append(f"FAILED: {reason}")

    def emit(self):
        """Output the standardized JSON to stdout."""
        output = {
            "tool": self.tool_name,
            "status": self.status,
            "target": self.target,
            "findings": {
                k: v for k, v in self.findings.items()
                if v  # Only include non-empty findings
            },
            "raw_output": "\n".join(self.raw_lines),
        }
        # Print JSON at the end, after all raw_lines
        print("\n__FORGE_OUTPUT_BEGIN__")
        print(json.dumps(output))
        print("__FORGE_OUTPUT_END__")


def parse_tool_output(stdout: str) -> Optional[Dict]:
    """
    Parse standardized tool output from stdout.
    Falls back to None if no structured output found.
    """
    begin_marker = "__FORGE_OUTPUT_BEGIN__"
    end_marker = "__FORGE_OUTPUT_END__"

    begin_idx = stdout.find(begin_marker)
    end_idx = stdout.find(end_marker)

    if begin_idx >= 0 and end_idx > begin_idx:
        json_str = stdout[begin_idx + len(begin_marker):end_idx].strip()
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return None
    return None
