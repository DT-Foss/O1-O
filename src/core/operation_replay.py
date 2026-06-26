"""Operation Replay Engine.

Records every FORGE operation (target, analysis steps, findings, mutations)
and enables replay on new targets. Learns which analysis strategies work
for which target types.

Use cases:
  - "Apply mDNSResponder methodology to all XPC daemons"
  - "Replay the fuzzing strategy that found the overflow"
  - "Which analysis pipeline works best for parsers?"

Storage: knowledge/operations.json (persistent)

Part of FORGE Phase Q: Intelligence & Replay.
"""
# Dependencies: none
# Depended by: none (leaf module)


import json
import hashlib
import time
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict


# ─── Operation Step Types ──────────────────────────────────────────

STEP_TYPES = {
    'analyze': 'Static analysis (AST, taint, CFG, xref)',
    'decompile': 'Binary decompilation pipeline',
    'fuzz': 'Fuzzing / input generation',
    'scan': 'Vulnerability pattern scan',
    'exploit': 'Exploit/payload generation',
    'mutate': 'Payload mutation for evasion',
    'verify': 'Formal verification',
    'report': 'Report generation',
    'assemble': 'Code assembly from triplets',
    'custom': 'Custom operation step',
}

# Target type classification
TARGET_TYPES = {
    'binary': ['elf', 'macho', 'pe', 'dll', 'so', 'dylib'],
    'source': ['py', 'c', 'cpp', 'rs', 'go', 'java', 'js'],
    'daemon': ['service', 'daemon', 'agent', 'launchd'],
    'parser': ['parser', 'deserializ', 'unmarshal', 'decode'],
    'network': ['socket', 'server', 'client', 'api', 'http'],
    'ipc': ['xpc', 'mach', 'dbus', 'pipe', 'shm'],
    'kernel': ['kext', 'driver', 'iokit', 'sysctl'],
    'crypto': ['encrypt', 'decrypt', 'hash', 'sign', 'tls'],
}


class OperationStep:
    """A single step in an operation."""

    def __init__(self, step_type: str, action: str, params: Dict = None,
                 result: Dict = None, duration_ms: int = 0):
        self.step_type = step_type
        self.action = action
        self.params = params or {}
        self.result = result or {}
        self.duration_ms = duration_ms
        self.timestamp = time.time()
        self.success = True
        self.findings_count = 0
        self.error = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'step_type': self.step_type,
            'action': self.action,
            'params': self.params,
            'result_summary': self._summarize_result(),
            'duration_ms': self.duration_ms,
            'timestamp': self.timestamp,
            'success': self.success,
            'findings_count': self.findings_count,
            'error': self.error,
        }

    def _summarize_result(self) -> Dict[str, Any]:
        """Summarize result without storing full output."""
        summary = {}
        if 'findings' in self.result:
            summary['findings_count'] = len(self.result['findings'])
        if 'score' in self.result:
            summary['score'] = self.result['score']
        if 'vulnerabilities' in self.result:
            summary['vuln_count'] = len(self.result['vulnerabilities'])
        if 'triplets' in self.result:
            summary['triplet_count'] = len(self.result['triplets'])
        if 'variants' in self.result:
            summary['variant_count'] = len(self.result['variants'])
        # Keep small results verbatim
        for key in ('severity', 'risk_level', 'primitive', 'confidence'):
            if key in self.result:
                summary[key] = self.result[key]
        return summary


class Operation:
    """A complete operation on a target."""

    def __init__(self, target: str, target_type: str = '', description: str = ''):
        self.id = hashlib.sha256(f"{target}{time.time()}".encode()).hexdigest()[:12]
        self.target = target
        self.target_type = target_type or self._classify_target(target)
        self.description = description
        self.steps: List[OperationStep] = []
        self.started = time.time()
        self.ended: float = 0
        self.success = False
        self.total_findings = 0
        self.tags: List[str] = []
        self.notes: str = ''

    def add_step(self, step: OperationStep):
        """Add a step to this operation."""
        self.steps.append(step)
        self.total_findings += step.findings_count

    def finish(self, success: bool = True):
        """Mark operation as complete."""
        self.ended = time.time()
        self.success = success
        self.total_findings = sum(s.findings_count for s in self.steps)

    def duration_seconds(self) -> float:
        end = self.ended or time.time()
        return end - self.started

    def step_sequence(self) -> List[str]:
        """Get the sequence of step types (the 'methodology')."""
        return [s.step_type for s in self.steps]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'target': self.target,
            'target_type': self.target_type,
            'description': self.description,
            'steps': [s.to_dict() for s in self.steps],
            'started': self.started,
            'ended': self.ended,
            'duration_s': round(self.duration_seconds(), 1),
            'success': self.success,
            'total_findings': self.total_findings,
            'step_sequence': self.step_sequence(),
            'tags': self.tags,
            'notes': self.notes,
        }

    @staticmethod
    def from_dict(d: Dict) -> 'Operation':
        """Reconstruct from dict."""
        op = Operation(d['target'], d.get('target_type', ''), d.get('description', ''))
        op.id = d['id']
        op.started = d.get('started', 0)
        op.ended = d.get('ended', 0)
        op.success = d.get('success', False)
        op.total_findings = d.get('total_findings', 0)
        op.tags = d.get('tags', [])
        op.notes = d.get('notes', '')
        for sd in d.get('steps', []):
            step = OperationStep(
                sd['step_type'], sd['action'],
                sd.get('params', {}), sd.get('result_summary', {}),
                sd.get('duration_ms', 0)
            )
            step.timestamp = sd.get('timestamp', 0)
            step.success = sd.get('success', True)
            step.findings_count = sd.get('findings_count', 0)
            step.error = sd.get('error', '')
            op.steps.append(step)
        return op

    def _classify_target(self, target: str) -> str:
        """Auto-classify target type."""
        target_lower = target.lower()
        for ttype, keywords in TARGET_TYPES.items():
            for kw in keywords:
                if kw in target_lower:
                    return ttype
        # Try file extension
        ext = os.path.splitext(target)[1].lstrip('.')
        for ttype, extensions in TARGET_TYPES.items():
            if ext in extensions:
                return ttype
        return 'unknown'


# ─── Operation Replay Engine ──────────────────────────────────────

class OperationReplayEngine:
    """Record, replay, and learn from FORGE operations."""

    def __init__(self, storage_path: str = None):
        if storage_path is None:
            base = Path(__file__).parent.parent / 'knowledge'
            storage_path = str(base / 'operations.json')

        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.operations: List[Operation] = self._load()
        self.active: Optional[Operation] = None

    def _load(self) -> List[Operation]:
        """Load operations from disk."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path) as f:
                    data = json.load(f)
                return [Operation.from_dict(d) for d in data]
            except (json.JSONDecodeError, KeyError):
                return []
        return []

    def _save(self):
        """Persist operations to disk."""
        with open(self.storage_path, 'w') as f:
            json.dump([op.to_dict() for op in self.operations], f, indent=2)

    # ─── Recording ─────────────────────────────────────────────

    def start_operation(self, target: str, description: str = '',
                        target_type: str = '') -> Operation:
        """Start recording a new operation."""
        self.active = Operation(target, target_type, description)
        return self.active

    def record_step(self, step_type: str, action: str, params: Dict = None,
                    result: Dict = None, duration_ms: int = 0,
                    findings_count: int = 0, success: bool = True,
                    error: str = '') -> Optional[OperationStep]:
        """Record a step in the active operation."""
        if not self.active:
            return None

        step = OperationStep(step_type, action, params, result, duration_ms)
        step.success = success
        step.findings_count = findings_count
        step.error = error
        self.active.add_step(step)
        return step

    def finish_operation(self, success: bool = True, tags: List[str] = None,
                         notes: str = '') -> Optional[Operation]:
        """Finish and store the active operation."""
        if not self.active:
            return None

        self.active.finish(success)
        if tags:
            self.active.tags = tags
        if notes:
            self.active.notes = notes

        self.operations.append(self.active)
        self._save()

        completed = self.active
        self.active = None
        return completed

    # ─── Replay ────────────────────────────────────────────────

    def get_methodology(self, operation_id: str) -> Optional[List[Dict]]:
        """Extract the methodology (step sequence) from an operation."""
        op = self._find_operation(operation_id)
        if not op:
            return None

        return [{
            'step': i + 1,
            'type': s.step_type,
            'action': s.action,
            'params': s.params,
            'findings_expected': s.findings_count,
        } for i, s in enumerate(op.steps)]

    def create_replay_plan(self, operation_id: str, new_target: str) -> Dict[str, Any]:
        """Create a replay plan by adapting an operation to a new target.

        Replaces target-specific parameters with the new target while
        preserving the methodology.
        """
        op = self._find_operation(operation_id)
        if not op:
            return {'error': f'Operation {operation_id} not found'}

        steps = []
        for i, s in enumerate(op.steps):
            adapted_params = dict(s.params)
            # Replace old target references
            for key, val in adapted_params.items():
                if isinstance(val, str) and op.target in val:
                    adapted_params[key] = val.replace(op.target, new_target)

            steps.append({
                'step': i + 1,
                'type': s.step_type,
                'action': s.action,
                'params': adapted_params,
                'original_findings': s.findings_count,
                'original_duration_ms': s.duration_ms,
            })

        return {
            'source_operation': op.id,
            'source_target': op.target,
            'new_target': new_target,
            'target_type': Operation('', '')._classify_target(new_target),
            'steps': steps,
            'total_steps': len(steps),
            'original_findings': op.total_findings,
            'original_success': op.success,
        }

    # ─── Learning / Intelligence ───────────────────────────────

    def best_methodology_for(self, target_type: str) -> Optional[Dict]:
        """Find the best methodology for a target type.

        Ranks by: findings_per_step * success_rate.
        """
        matching = [op for op in self.operations
                    if op.target_type == target_type and op.success]

        if not matching:
            # Try partial match
            matching = [op for op in self.operations
                        if target_type in op.target_type or op.target_type in target_type]

        if not matching:
            return None

        # Score each operation
        scored = []
        for op in matching:
            n_steps = max(len(op.steps), 1)
            findings_per_step = op.total_findings / n_steps
            score = findings_per_step * (1.0 if op.success else 0.3)
            scored.append((score, op))

        scored.sort(key=lambda x: -x[0])
        best_score, best_op = scored[0]

        return {
            'operation_id': best_op.id,
            'target': best_op.target,
            'target_type': best_op.target_type,
            'score': round(best_score, 2),
            'methodology': best_op.step_sequence(),
            'total_findings': best_op.total_findings,
            'duration_s': round(best_op.duration_seconds(), 1),
            'steps': len(best_op.steps),
        }

    def strategy_stats(self) -> Dict[str, Any]:
        """Aggregate statistics across all operations."""
        if not self.operations:
            return {'total': 0}

        by_type = defaultdict(list)
        by_step = defaultdict(lambda: {'count': 0, 'findings': 0, 'success': 0})
        step_sequences = defaultdict(int)

        for op in self.operations:
            by_type[op.target_type].append(op)
            seq = ' -> '.join(op.step_sequence())
            step_sequences[seq] += 1

            for step in op.steps:
                s = by_step[step.step_type]
                s['count'] += 1
                s['findings'] += step.findings_count
                if step.success:
                    s['success'] += 1

        type_stats = {}
        for ttype, ops in by_type.items():
            successful = [op for op in ops if op.success]
            type_stats[ttype] = {
                'total': len(ops),
                'successful': len(successful),
                'avg_findings': sum(op.total_findings for op in ops) / len(ops),
                'avg_duration_s': sum(op.duration_seconds() for op in ops) / len(ops),
            }

        step_stats = {}
        for stype, s in by_step.items():
            step_stats[stype] = {
                'count': s['count'],
                'total_findings': s['findings'],
                'success_rate': s['success'] / max(s['count'], 1),
                'avg_findings': s['findings'] / max(s['count'], 1),
            }

        # Most effective sequences
        top_sequences = sorted(step_sequences.items(), key=lambda x: -x[1])[:5]

        return {
            'total_operations': len(self.operations),
            'successful': sum(1 for op in self.operations if op.success),
            'total_findings': sum(op.total_findings for op in self.operations),
            'by_target_type': type_stats,
            'by_step_type': step_stats,
            'top_sequences': [{'sequence': s, 'count': c} for s, c in top_sequences],
        }

    def similar_operations(self, target: str, limit: int = 5) -> List[Dict]:
        """Find operations on similar targets."""
        target_type = Operation('', '')._classify_target(target)
        target_lower = target.lower()

        scored = []
        for op in self.operations:
            score = 0
            # Same target type
            if op.target_type == target_type:
                score += 5
            # Name similarity
            op_lower = op.target.lower()
            if target_lower in op_lower or op_lower in target_lower:
                score += 10
            # Shared words
            target_words = set(target_lower.split('_'))
            op_words = set(op_lower.split('_'))
            shared = target_words & op_words
            score += len(shared) * 2
            # Tag overlap
            for tag in op.tags:
                if tag in target_lower:
                    score += 3

            if score > 0:
                scored.append((score, op))

        scored.sort(key=lambda x: -x[0])

        return [{
            'operation_id': op.id,
            'target': op.target,
            'target_type': op.target_type,
            'similarity': score,
            'methodology': op.step_sequence(),
            'findings': op.total_findings,
            'success': op.success,
        } for score, op in scored[:limit]]

    # ─── Triplet Export ────────────────────────────────────────

    def to_triplets(self) -> List[Dict[str, str]]:
        """Export learned strategies as causal triplets."""
        triplets = []

        # Per-operation triplets
        for op in self.operations:
            if not op.success:
                continue

            seq = ' -> '.join(op.step_sequence())
            triplets.append({
                'trigger': f'analyze {op.target_type} target',
                'mechanism': seq,
                'outcome': f'{op.total_findings} findings in {op.duration_seconds():.0f}s',
                'confidence': 0.8,
            })

            # Per-step findings
            for step in op.steps:
                if step.findings_count > 0:
                    triplets.append({
                        'trigger': f'{step.step_type} on {op.target_type}',
                        'mechanism': step.action,
                        'outcome': f'{step.findings_count} findings',
                        'confidence': 0.7,
                    })

        return triplets

    # ─── Formatting ────────────────────────────────────────────

    def format_operation(self, operation_id: str) -> str:
        """Format an operation for display."""
        op = self._find_operation(operation_id)
        if not op:
            return f'Operation {operation_id} not found'

        status = 'SUCCESS' if op.success else 'FAILED'
        lines = [
            f"OPERATION {op.id}",
            f"{'=' * 50}",
            f"  Target: {op.target} ({op.target_type})",
            f"  Status: {status}",
            f"  Duration: {op.duration_seconds():.1f}s",
            f"  Findings: {op.total_findings}",
            f"  Steps: {len(op.steps)}",
        ]
        if op.tags:
            lines.append(f"  Tags: {', '.join(op.tags)}")
        if op.description:
            lines.append(f"  Description: {op.description}")
        lines.append(f"  Methodology: {' -> '.join(op.step_sequence())}")
        lines.append('')

        for i, step in enumerate(op.steps, 1):
            status_icon = 'OK' if step.success else 'FAIL'
            lines.append(
                f"  Step {i}: [{status_icon}] {step.step_type}: {step.action} "
                f"({step.duration_ms}ms, {step.findings_count} findings)"
            )
            if step.error:
                lines.append(f"          Error: {step.error}")

        return '\n'.join(lines)

    def format_list(self, limit: int = 20) -> str:
        """Format operation list for display."""
        if not self.operations:
            return "No operations recorded."

        lines = [
            f"OPERATIONS ({len(self.operations)} total)",
            f"{'=' * 70}",
            f"  {'ID':<14} {'Target':<25} {'Type':<10} {'Steps':<6} {'Findings':<9} {'Status'}",
            f"  {'-'*14} {'-'*25} {'-'*10} {'-'*6} {'-'*9} {'-'*6}",
        ]

        for op in self.operations[-limit:]:
            status = 'OK' if op.success else 'FAIL'
            target_short = op.target[:24]
            lines.append(
                f"  {op.id:<14} {target_short:<25} {op.target_type:<10} "
                f"{len(op.steps):<6} {op.total_findings:<9} {status}"
            )

        return '\n'.join(lines)

    def format_stats(self) -> str:
        """Format strategy statistics."""
        stats = self.strategy_stats()
        if stats['total_operations'] == 0:
            return "No operations recorded yet."

        lines = [
            f"OPERATION STRATEGY STATS",
            f"{'=' * 50}",
            f"  Total Operations: {stats['total_operations']}",
            f"  Successful: {stats['successful']}",
            f"  Total Findings: {stats['total_findings']}",
            '',
            f"  BY TARGET TYPE:",
        ]

        for ttype, ts in sorted(stats['by_target_type'].items()):
            lines.append(
                f"    {ttype:<12} {ts['total']} ops, "
                f"{ts['successful']} success, "
                f"avg {ts['avg_findings']:.1f} findings"
            )

        lines.extend(['', '  BY STEP TYPE:'])
        for stype, ss in sorted(stats['by_step_type'].items()):
            lines.append(
                f"    {stype:<12} {ss['count']} uses, "
                f"{ss['success_rate']:.0%} success, "
                f"avg {ss['avg_findings']:.1f} findings"
            )

        if stats['top_sequences']:
            lines.extend(['', '  TOP METHODOLOGIES:'])
            for seq_info in stats['top_sequences']:
                lines.append(f"    [{seq_info['count']}x] {seq_info['sequence']}")

        return '\n'.join(lines)

    # ─── Internal ──────────────────────────────────────────────

    def _find_operation(self, operation_id: str) -> Optional[Operation]:
        """Find operation by ID (prefix match)."""
        for op in self.operations:
            if op.id.startswith(operation_id):
                return op
        return None
