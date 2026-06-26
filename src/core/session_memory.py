"""
Session Memory — Track conversation context across turns + persistent project.causal

Features:
1. Multi-turn dialogue state tracking (resolve "it", "that", "the previous one")
2. Entity co-reference resolution across turns
3. Incremental intent detection ("add X to it", "now also do Y")
4. Persistent project.causal for cross-session learning
5. Topic tracking (what domain/area the user is working in)
6. Slot filling (accumulate parameters across multiple turns)
"""
# Dependencies: none
# Depended by: none (leaf module)


import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple


class SessionMemory:
    """Track conversation context across turns with persistent state"""

    # Pronouns and references that need resolution
    PRONOUNS = {'it', 'that', 'them', 'this', 'there', 'those', 'these'}
    REFERENCE_PHRASES = {
        'the file', 'that script', 'the code', 'the output', 'the result',
        'the previous', 'the last one', 'same thing', 'that function',
        'the error', 'the bug', 'the issue', 'the data', 'the server',
    }

    # Incremental markers — user is modifying previous work
    INCREMENTAL_MARKERS = {
        'add', 'also', 'then', 'now', 'refactor', 'append', 'save', 'fix',
        'change', 'modify', 'update', 'remove', 'delete', 'replace',
        'extend', 'improve', 'optimize', 'but', 'instead', 'keep',
    }

    # Topic keywords for domain tracking
    TOPIC_KEYWORDS = {
        'web': {'flask', 'django', 'fastapi', 'html', 'css', 'api', 'http', 'server', 'endpoint'},
        'data': {'csv', 'json', 'pandas', 'numpy', 'dataframe', 'database', 'sql', 'sqlite'},
        'security': {'scan', 'exploit', 'vulnerability', 'hash', 'encrypt', 'firewall', 'nmap'},
        'devops': {'docker', 'kubernetes', 'deploy', 'ci', 'cd', 'ansible', 'terraform'},
        'ml': {'model', 'train', 'predict', 'neural', 'tensorflow', 'pytorch', 'sklearn'},
        'network': {'socket', 'tcp', 'udp', 'http', 'dns', 'ping', 'port', 'ssh'},
        'file': {'file', 'directory', 'path', 'read', 'write', 'copy', 'move', 'rename'},
    }

    def __init__(self, project_dir: Optional[Path] = None):
        self.history: List[Dict[str, Any]] = []
        self.current_script: Optional[str] = None
        self.current_entities: Set[str] = set()
        self.current_topic: Optional[str] = None
        self.slots: Dict[str, Any] = {}  # Accumulated parameters
        self.entity_history: List[Set[str]] = []  # Entity sets per turn
        self.success_count: int = 0
        self.fail_count: int = 0

        # Persistent project memory
        self.project_dir = project_dir or Path.cwd()
        self.project_file = self.project_dir / '.forge_session.json'
        self._load_persistent()

    def _load_persistent(self):
        """Load persistent session state from project directory"""
        if self.project_file.exists():
            try:
                with open(self.project_file) as f:
                    state = json.load(f)
                self.slots = state.get('slots', {})
                self.current_topic = state.get('topic', None)
                self.success_count = state.get('successes', 0)
                self.fail_count = state.get('failures', 0)
                # Restore last entities for cross-session continuity
                last_entities = state.get('last_entities', [])
                self.current_entities = set(last_entities)
            except (json.JSONDecodeError, KeyError):
                pass

    def _save_persistent(self):
        """Save session state for cross-session persistence"""
        state = {
            'slots': self.slots,
            'topic': self.current_topic,
            'successes': self.success_count,
            'failures': self.fail_count,
            'last_entities': list(self.current_entities),
            'last_updated': time.time(),
        }
        try:
            with open(self.project_file, 'w') as f:
                json.dump(state, f, indent=2)
        except (OSError, PermissionError):
            pass

    def add_turn(self, intent: Dict[str, Any], result: str,
                 script: Optional[str] = None, success: bool = True):
        """Add a turn to the session history"""
        turn = {
            'intent': intent,
            'result': result,
            'script': script,
            'success': success,
            'timestamp': time.time(),
        }
        self.history.append(turn)

        if script:
            self.current_script = script

        if success:
            self.success_count += 1
        else:
            self.fail_count += 1

        # Track entities per turn
        turn_entities = set()
        for entity in intent.get('entities', []):
            name = entity['matched']
            self.current_entities.add(name)
            turn_entities.add(name)
        self.entity_history.append(turn_entities)

        # Update topic
        self._update_topic(intent)

        # Update slots from entities
        self._update_slots(intent)

        # Persist
        self._save_persistent()

    def get_context(self) -> Dict[str, Any]:
        """Return relevant context for next intent"""
        return {
            'current_script': self.current_script,
            'current_entities': list(self.current_entities),
            'last_intent': self.history[-1]['intent'] if self.history else None,
            'topic': self.current_topic,
            'slots': dict(self.slots),
            'turn_count': len(self.history),
            'success_rate': (self.success_count / max(1, self.success_count + self.fail_count)),
        }

    def resolve_references(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve pronouns, references, and incremental markers to previous context"""
        raw = intent.get('raw', '').lower()
        tokens = set(intent.get('tokens', []))

        # Check for pronouns
        has_pronoun = any(p in tokens for p in self.PRONOUNS)
        has_reference = any(p in raw for p in self.REFERENCE_PHRASES)
        is_incremental = any(m in tokens for m in self.INCREMENTAL_MARKERS)

        # Detect if this is a follow-up turn
        is_followup = has_pronoun or has_reference or is_incremental

        if is_followup and self.current_entities:
            # Add previous entities to the current intent
            existing_entities = {e['matched'] for e in intent.get('entities', [])}
            for entity in self.current_entities:
                if entity not in existing_entities:
                    intent.setdefault('entities', []).append({
                        'matched': entity,
                        'confidence': 0.7,
                        'is_contextual': True,
                    })

            # Mark intent as incremental for the assembler
            intent['is_incremental'] = True
            intent['context_script'] = self.current_script
            intent['context_topic'] = self.current_topic

        # Resolve specific reference phrases
        if 'the error' in raw or 'the bug' in raw:
            # Look for last error in history
            for turn in reversed(self.history):
                if not turn.get('success', True):
                    intent['context_error'] = turn.get('result', '')
                    break

        if 'the output' in raw or 'the result' in raw:
            for turn in reversed(self.history):
                if turn.get('success', True) and turn.get('script'):
                    intent['context_output'] = turn.get('result', '')
                    break

        # Slot filling: accumulate parameters from conversation
        self._fill_slots_from_intent(intent)

        return intent

    def _update_topic(self, intent: Dict[str, Any]):
        """Track the current topic/domain"""
        tokens = set(intent.get('tokens', []))
        entity_names = {e['matched'].lower() for e in intent.get('entities', [])}
        all_words = tokens | entity_names

        best_topic = None
        best_score = 0

        for topic, keywords in self.TOPIC_KEYWORDS.items():
            overlap = len(all_words & keywords)
            if overlap > best_score:
                best_score = overlap
                best_topic = topic

        if best_score >= 1:
            self.current_topic = best_topic

    def _update_slots(self, intent: Dict[str, Any]):
        """Update accumulated slots from intent entities"""
        for entity in intent.get('entities', []):
            name = entity['matched']
            # Detect slot type from entity name patterns
            if name.endswith('.py') or name.endswith('.js') or name.endswith('.sh'):
                self.slots['file'] = name
            elif name.startswith('http') or name.startswith('www'):
                self.slots['url'] = name
            elif '/' in name or '\\' in name:
                self.slots['path'] = name
            elif '@' in name:
                self.slots['email'] = name
            elif ':' in name and name.replace(':', '').replace('.', '').isdigit():
                self.slots['host'] = name

    def _fill_slots_from_intent(self, intent: Dict[str, Any]):
        """Fill intent with accumulated slot values"""
        # If intent is missing a path/url/file, fill from slots
        entities = intent.get('entities', [])
        entity_names = {e['matched'] for e in entities}

        for slot_type, slot_value in self.slots.items():
            if slot_value not in entity_names:
                # Check if intent needs this slot
                raw = intent.get('raw', '').lower()
                if slot_type == 'file' and ('file' in raw or 'script' in raw):
                    intent.setdefault('entities', []).append({
                        'matched': slot_value,
                        'confidence': 0.6,
                        'is_slot_fill': True,
                        'slot_type': slot_type,
                    })
                elif slot_type == 'url' and ('url' in raw or 'download' in raw or 'fetch' in raw):
                    intent.setdefault('entities', []).append({
                        'matched': slot_value,
                        'confidence': 0.6,
                        'is_slot_fill': True,
                        'slot_type': slot_type,
                    })

    def get_recent_entities(self, n_turns: int = 3) -> Set[str]:
        """Get entities from recent turns"""
        recent = set()
        for entity_set in self.entity_history[-n_turns:]:
            recent |= entity_set
        return recent

    def get_topic_history(self) -> List[str]:
        """Get the sequence of topics discussed"""
        topics = []
        for turn in self.history:
            tokens = set(turn['intent'].get('tokens', []))
            for topic, keywords in self.TOPIC_KEYWORDS.items():
                if tokens & keywords:
                    if not topics or topics[-1] != topic:
                        topics.append(topic)
                    break
        return topics

    def clear(self):
        """Clear the session memory"""
        self.history = []
        self.current_script = None
        self.current_entities = set()
        self.entity_history = []
        self.slots = {}
        self.current_topic = None
