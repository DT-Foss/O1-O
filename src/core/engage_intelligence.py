#!/usr/bin/env python3
"""
Engage Intelligence — V2 Intelligence layer for V1's /engage pipeline.

This module provides the Target Model + Solver to forge_live.py's /engage
WITHOUT replacing the existing pipeline. It hooks into the existing flow:

1. After Phase 1 (Recon): Build Target Model from discovered services
2. Instead of Phase 2 (static auto_configure): Solver plans dynamically
3. After each Phase 3 deploy: Feed results into Target Model for learning
4. After Phase 4 (Chaining): Solver plans lateral movement + pivot

Usage in forge_live.py:
    from core.engage_intelligence import EngageIntelligence
    intel = EngageIntelligence(target_ip, services, objective)
    # Instead of auto_configure:
    recommendations = intel.plan_initial(services, objective)
    # After each deploy:
    intel.learn_from_result(tool_desc, deploy_result)
    # After chaining:
    lateral_plan = intel.plan_lateral()
"""

from core.target_model import TargetModel
from core.target_solver import TargetSolver
from typing import List, Dict, Tuple, Optional


class EngageIntelligence:
    """V2 Intelligence layer that plugs into V1's /engage pipeline."""

    def __init__(self, target_ip: str, fragment_keys: set = None):
        self.target = TargetModel(ip=target_ip)
        self.solver = TargetSolver(self.target, fragment_keys=fragment_keys or set())

    def ingest_recon(self, services: list):
        """Build Target Model from V1's LiveReconEngine output."""
        for svc in services:
            port = svc.get("port", 0)
            proto = svc.get("service", "unknown")
            banner = svc.get("banner", "")
            self.target.add_service(port, proto, "open", banner)

    def plan_initial(self, services: list, objective: str,
                     existing_recommendations: list) -> list:
        """
        Enhance V1's static recommendations with V2 intelligence.

        Doesn't REPLACE auto_configure — augments it.
        Returns the same format: [(tool_description, config_dict), ...]
        """
        self.ingest_recon(services)

        # Start with V1's recommendations (they're good, based on service mapping)
        enhanced = list(existing_recommendations)

        # Add V2's recon-first tools at the beginning
        # (credential harvest + post-exploit enum run FIRST)
        v2_recon = []
        if not any("credential" in r[0].lower() and "harvester" in r[0].lower()
                   for r in enhanced):
            v2_recon.append((
                "credential harvester stdlib",
                {"target": self.target.ip}
            ))
        if not any("post" in r[0].lower() and "exploit" in r[0].lower()
                   for r in enhanced):
            v2_recon.append((
                "post exploitation enumeration stdlib",
                {"target": self.target.ip}
            ))

        return v2_recon + enhanced

    def learn_from_result(self, tool_desc: str, deploy_result: dict,
                          tool_config: dict = None):
        """
        Feed a deploy result into the Target Model for state tracking.
        Called after each tool deploy in Phase 3.
        """
        if not deploy_result:
            return

        status = deploy_result.get("status", "unknown")
        stdout = deploy_result.get("stdout", "")
        stderr = deploy_result.get("stderr", "")
        exit_code = deploy_result.get("exit_code", -1)

        # Determine port from config
        port = 0
        if tool_config:
            try:
                port = int(tool_config.get("port", 0))
            except (ValueError, TypeError):
                pass

        # Record attempt
        self.target.record_attempt(
            tool=tool_desc, intent=tool_desc,
            port=port, status="success" if status == "success" else "failed",
            stdout=stdout, stderr=stderr, exit_code=exit_code,
        )

        # Failure learning for the solver
        if status != "success":
            reason = deploy_result.get("reason", "execution_failed")
            self.solver.learn_from_failure(tool_desc, reason, stderr or stdout)

    def plan_lateral(self) -> List[Dict]:
        """
        After initial tools ran, check if we found lateral movement opportunities.
        Returns a list of lateral actions to execute.
        """
        actions = []

        ssh_keys = getattr(self.target, "ssh_keys_found", [])
        lateral_targets = getattr(self.target, "lateral_targets_found", [])

        if not ssh_keys or not lateral_targets:
            return actions

        unencrypted = [k for k in ssh_keys if not k.get("encrypted", True)]
        if not unencrypted:
            return actions

        key_path = unencrypted[0]["path"]

        # Skip own IPs
        own_ips = {self.target.ip}
        own_ips.update(getattr(self.target, "internal_ips", []))

        # Failed lateral IPs
        failed_ips = set()
        for a in self.target.attempts:
            if "lateral" in a.tool and a.status == "failed":
                for part in a.tool.split("_"):
                    if part.count(".") == 3:
                        failed_ips.add(part)

        lateral_users = ["devops", "deploy", "developer", "admin", "root"]

        for lt_ip in lateral_targets:
            if lt_ip in own_ips or lt_ip in failed_ips:
                continue
            actions.append({
                "type": "lateral_ssh_key",
                "target_ip": lt_ip,
                "username": lateral_users[0],  # Try most likely first
                "key_path": key_path,
                "intent": f"create ssh connect stdlib targeting {lt_ip}",
                "config": {
                    "target": lt_ip,
                    "port": "22",
                    "username": lateral_users[0],
                    "ssh_key": key_path,
                },
            })

        return actions

    def plan_pivot(self, lateral_ip: str, lateral_user: str,
                   lateral_key: str) -> List[Dict]:
        """
        After successful lateral movement, plan post-lateral actions.
        Returns pivot tool intents for the FORGE pipeline.
        """
        return [
            {
                "type": "pivot_cred_harvest",
                "intent": f"create pivot credential harvest targeting {lateral_ip}",
                "config": {
                    "target": lateral_ip,
                    "username": lateral_user,
                    "ssh_key": lateral_key,
                    "port": "22",
                },
            },
            {
                "type": "pivot_privesc",
                "intent": f"create pivot privesc check targeting {lateral_ip}",
                "config": {
                    "target": lateral_ip,
                    "username": lateral_user,
                    "ssh_key": lateral_key,
                    "port": "22",
                },
            },
        ]

    def should_skip_tool(self, tool_desc: str) -> Tuple[bool, str]:
        """Check if a tool should be skipped based on learned intelligence."""
        tool_lower = tool_desc.lower()

        # Check blacklist
        if self.solver._is_blacklisted(tool_lower):
            reason = self.solver.blacklisted_reasons.get(tool_lower, "blacklisted")
            return True, reason

        # Check if SSH is already accessed (don't brute force what we have)
        if any(w in tool_lower for w in ["ssh brute", "ssh enum", "ssh credential"]):
            has_ssh = any(
                a.status == "success" and "ssh" in a.tool.lower()
                for a in self.target.attempts
            )
            if has_ssh:
                return True, "SSH access already established"

        return False, ""

    def get_state_summary(self) -> str:
        """Human-readable summary of what we know about the target."""
        return self.target.summary()

    def get_credentials(self) -> list:
        return self.target.credentials

    def get_ssh_keys(self) -> list:
        return getattr(self.target, "ssh_keys_found", [])

    def get_lateral_targets(self) -> list:
        return getattr(self.target, "lateral_targets_found", [])
