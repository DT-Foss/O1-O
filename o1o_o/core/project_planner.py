# Dependencies: knowledge_engine
# Depended by: project_generator

import re
from pathlib import Path
from typing import List, Dict, Any
from o1o_o.core.knowledge_engine import KnowledgeEngine

class ProjectPlanner:
    """
    V8 Component: Decomposes complex intents into a multi-file system architecture.
    Identifies 'Agent' boundaries based on knowledge domain clusters.
    """
    def __init__(self, knowledge_engine: KnowledgeEngine):
        self.ke = knowledge_engine
        
    def plan(self, primary_intent: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Decomposes a primary intent into a list of sub-agent specifications.
        Example: 'scaper that saves to db' -> [ScraperAgent, DBAgent]
        """
        raw_prompt = primary_intent.get('raw', '')
        entities = primary_intent.get('entities', [])
        
        # 1. Identify "Agent Boundaries"
        sub_tasks = self._segment_intent(raw_prompt, entities)
        
        # 2. Extract Shared State (Z-Sync)
        # We look for entities that appear across segments or are critical for links
        shared_entities = self._extract_shared_entities(sub_tasks, entities)
        
        project_plan = {
            "name": f"project_{int(re.sub(r'[^0-9]', '', raw_prompt[:5]) or '0')}",
            "manifest": shared_entities,
            "agents": []
        }
        
        for i, task_text in enumerate(sub_tasks):
            deps = [project_plan['agents'][j]['name'] for j in range(len(project_plan['agents']))]
            
            agent_spec = {
                "id": i + 1,
                "name": self._generate_agent_name(task_text, i),
                "intent_raw": task_text,
                "dependencies": deps,
                "role": self._infer_role(task_text),
                "exports": self._identify_exports(task_text, shared_entities)
            }
            project_plan['agents'].append(agent_spec)
            
        # 3. Add Orchestrator Scripts (Launcher/Cron)
        self._add_orchestration_layer(project_plan, raw_prompt)
            
        return project_plan

    def _add_orchestration_layer(self, plan: Dict[str, Any], raw_prompt: str):
        """Adds launcher and cron scripts if needed."""
        # Launcher script
        launcher = ["#!/bin/bash", "# FORGE Project Launcher", ""]
        for agent in plan['agents']:
            launcher.append(f"echo 'Running {agent['name']}...'")
            launcher.append(f"python3 {agent['name']}.py")
            
        plan['launcher_script'] = "\n".join(launcher)
        
        # Cron job (if hourly/daily/cron mentioned)
        if any(kw in raw_prompt.lower() for kw in ['hourly', 'cron', 'every', 'schedule']):
            plan['cron_job'] = f"0 * * * * cd {Path.cwd()} && ./run_all.sh"

    def _extract_shared_entities(self, tasks: List[str], entities: List[str]) -> Dict[str, Any]:
        """Identifies which variables need to be synced across agents."""
        manifest = {}
        # Simple extraction: if a task mentions a filename or database, it's shared
        for task in tasks:
            # Match potential filenames or specific entities
            files = re.findall(r'(\w+\.(?:json|csv|db|txt|html))', task)
            for f in files:
                manifest[f.split('.')[0] + "_path"] = f
            
            # Look for URLs or hostnames - improved regex
            hosts = re.findall(r'https?://([a-zA-Z0-9.-]+)|www\.([a-zA-Z0-9.-]+)', task.lower())
            for h_tuple in hosts:
                h = h_tuple[0] or h_tuple[1]
                if h and not h.endswith(('.py', '.db', '.causal')):
                    manifest['target_host'] = h

            # Look for emails
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', task)
            if emails:
                manifest['admin_email'] = emails[0]
                
        # Default entities if none found but needed for domain link
        if not manifest and any('db' in t.lower() for t in tasks):
            manifest['database_name'] = 'forge_project.db'
            
        return manifest

    def _identify_exports(self, task_text: str, shared_entities: Dict[str, Any]) -> List[str]:
        """Lists which shared variables this specific agent is responsible for creating/using."""
        return [k for k, v in shared_entities.items() if v.lower() in task_text.lower() or k.split('_')[0] in task_text.lower()]

    def _segment_intent(self, raw_prompt: str, entities: List[str]) -> List[str]:
        """Splits a prompt into logical sub-tasks, including list detection."""
        # 1. Detect explicit list after colon
        if ':' in raw_prompt:
            intro, list_part = raw_prompt.split(':', 1)
            # If list_part contains many commas or numbers, split it
            items = re.split(r',\s*|\n\s*|\d+\.\s*', list_part)
            segments = [p.strip() for p in items if len(p.strip()) > 2]
            if len(segments) > 2:
                # Keep the intro as a potential orchestrator task or prepend it
                return [intro.strip()] + segments

        # 2. Detect numbered or bulleted lists
        list_parts = re.split(r'\n\s*[\d\-\*\u2022]+\.?\s+', raw_prompt)
        if len(list_parts) > 2:
            return [p.strip() for p in list_parts if len(p.strip()) > 5]

        # 3. Split by common conjunctions
        parts = re.split(r' and | then | also | thereafter |;|\n', raw_prompt, flags=re.IGNORECASE)
        segments = [p.strip() for p in parts if len(p.strip()) > 5]
        
        if not segments:
            segments = [raw_prompt]
            
        return segments

    def _generate_agent_name(self, task_text: str, index: int) -> str:
        """Determines a file/agent name based on task content."""
        if 'scrape' in task_text.lower() or 'web' in task_text.lower():
            return f"scraper_agent_{index+1}"
        if 'db' in task_text.lower() or 'database' in task_text.lower() or 'sql' in task_text.lower():
            return f"db_agent_{index+1}"
        if 'mail' in task_text.lower() or 'notify' in task_text.lower():
            return f"notifier_agent_{index+1}"
        if 'cron' in task_text.lower() or 'schedule' in task_text.lower() or 'hourly' in task_text.lower():
            return f"scheduler_agent_{index+1}"
            
        return f"worker_agent_{index+1}"

    def _infer_role(self, task_text: str) -> str:
        """Assigns a technical role to the segment."""
        if 'scrape' in task_text.lower(): return "COLLECTOR"
        if 'db' in task_text.lower(): return "PERSISTENCE"
        if 'mail' in task_text.lower(): return "NOTIFIER"
        if 'cron' in task_text.lower(): return "ORCHESTRATOR"
        return "PROCESSOR"
