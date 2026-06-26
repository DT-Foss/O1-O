"""
Intent Parser — Natural language → Intent object (KI-free)

Converts user input into structured intent via:
1. Tokenization (split + stopword removal + stemming)
2. Entity extraction (fuzzy matching against knowledge base)
3. Intent classification (keyword combination rules)
4. Parameter extraction (paths, formats, numbers)
"""
# Dependencies: none
# Depended by: none (leaf module)


import re
from typing import Dict, List, Any
import jellyfish


class IntentParser:
    """Parse natural language into structured intent without LLM"""

    # Stopwords to remove (English)
    STOPWORDS = {
        'a', 'an', 'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
        'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'be',
        'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
        'would', 'should', 'could', 'may', 'might', 'can', 'this', 'that',
        'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they', 'my',
        'your', 'his', 'her', 'its', 'our', 'their', 'me', 'him', 'her', 'us',
        'them', 'all', 'some', 'any', 'no', 'not', 'so',
        'com', 'org', 'net', 'www', 'http', 'https', 'example'
    }

    # Intent keywords
    BUILD_KEYWORDS = {
        'build', 'create', 'make', 'generate', 'write', 'code', 'script',
        'program', 'develop', 'implement', 'construct', 'run', 'execute',
        'add', 'append', 'refactor', 'update', 'modify', 'now', 'also'
    }

    CHAT_KEYWORDS = {
        'what', 'why', 'how', 'when', 'where', 'who', 'which', 'explain',
        'tell', 'describe', 'define', 'mean'
    }

    # Action verbs that imply BUILD even without explicit "build" keyword
    ACTION_VERBS = {
        'list', 'read', 'parse', 'convert', 'download', 'scrape', 'fetch',
        'extract', 'sort', 'filter', 'merge', 'split', 'count', 'rename',
        'copy', 'move', 'delete', 'search', 'find', 'replace', 'process',
        'transform', 'analyze', 'plot', 'send', 'upload', 'compress',
        'encrypt', 'hash', 'validate', 'scan', 'monitor', 'serve',
        'save', 'write', 'archive', 'backup', 'export', 'import',
        # Added for better composition detection
        'create', 'build', 'generate', 'make', 'design', 'implement',
        'detect', 'check', 'test', 'run', 'execute', 'compile',
        'optimize', 'refactor', 'verify', 'report', 'summarize',
        'generate', 'build', 'develop', 'construct', 'assemble',
    }

    # Tokens that imply the user wants visible output
    OUTPUT_TOKENS = {
        'list', 'show', 'print', 'display', 'output', 'count', 'find',
        'search', 'check', 'view', 'get', 'fetch', 'see',
    }

    # Conjunctions that indicate multi-step composition
    COMPOSITION_CONJUNCTIONS = {'and', 'then', 'also', 'plus', 'into'}

    DEBUG_KEYWORDS = {
        'error', 'crash', 'bug', 'fix', 'broken', 'wrong', 'fail', 'failing',
        'debug', 'troubleshoot', 'issue', 'problem'
    }

    LEARN_KEYWORDS = {
        'learn', 'teach', 'remember',
    }

    def __init__(self, knowledge_engine):
        self.knowledge = knowledge_engine

    def tokenize(self, text: str) -> List[str]:
        """Split text into tokens, remove stopwords"""
        # Lowercase and split
        tokens = re.findall(r'\b\w+\b', text.lower())

        # Remove stopwords
        tokens = [t for t in tokens if t not in self.STOPWORDS]

        return tokens

    def stem(self, word: str) -> str:
        """Simple stemming (remove common endings)"""
        # Very basic stemmer - remove common suffixes
        suffixes = ['ing', 'ed', 'es', 's', 'er', 'ly']
        for suffix in suffixes:
            if word.endswith(suffix) and len(word) > len(suffix) + 2:
                return word[:-len(suffix)]
        return word

    def _disambiguate_entity(self, token: str, context_tokens: List[str]) -> str:
        """
        Disambiguate entity based on context.

        Examples:
        - "command" + ["botnet", "c2", "protocol"] → "c2_command"
        - "command" + ["pattern", "undo", "redo"] → "command_pattern"
        - "injection" + ["dll", "windows", "api"] → "dll_injection"
        - "encryption" + ["aes", "ransomware", "files"] → "aes_encryption"
        """
        token_lower = token.lower()
        context_set = set(context_tokens)

        # C2 Protocol disambiguation
        if token_lower in ["command", "control"]:
            c2_keywords = {"botnet", "c2", "protocol", "fallback", "server", "agent", "malware", "exploit"}
            design_keywords = {"pattern", "undo", "redo", "history", "design"}

            if context_set & c2_keywords:
                return "c2_command"  # C2 protocol context
            elif context_set & design_keywords:
                return "command_pattern"  # Design pattern context

        # DLL Injection disambiguation
        if token_lower == "injection":
            dll_keywords = {"dll", "windows", "api", "createremotethread", "loadlibrarya", "inject"}
            code_keywords = {"code", "inject", "process", "memory"}

            if context_set & dll_keywords:
                return "dll_injection"  # Windows DLL context
            elif "ransomware" in context_set or "encrypt" in context_set:
                return "code_injection"  # Malware code injection

        # Encryption disambiguation
        if token_lower in ["encryption", "encrypt"]:
            ransomware_keywords = {"ransomware", "aes", "files", "bitcoin", "payment", "demand"}
            qr_keywords = {"qr", "code", "qrcode", "generate"}

            if context_set & ransomware_keywords:
                return "aes_encryption"  # AES file encryption
            elif context_set & qr_keywords:
                return "qr_generation"  # QR code generation

        # Ransomware disambiguation
        if token_lower == "code":
            ransomware_keywords = {"ransomware", "encrypt", "bitcoin", "payment", "demand"}
            qr_keywords = {"qr", "qrcode"}

            if context_set & ransomware_keywords:
                return "ransomware_code"
            elif context_set & qr_keywords:
                return "qr_code"

        # Default: return original
        return token_lower

    def extract_entities(self, tokens: List[str]) -> List[Dict[str, Any]]:
        """Extract entities via fuzzy matching against knowledge base"""
        entities = []

        # Get known entities from knowledge base
        known_entities = self.knowledge.get_all_entities()
        # Build lowercase set for fast exact-match on short tokens
        known_lower = {e.lower(): e for e in known_entities}

        for token in tokens:
            stemmed = self.stem(token)

            # Apply disambiguation based on context
            disambiguated = self._disambiguate_entity(token, tokens)

            # Exact match first (original token)
            if token in known_entities:
                entities.append({
                    'original': token,
                    'matched': token,
                    'confidence': 1.0,
                    'method': 'exact',
                    'disambiguated': disambiguated if disambiguated != token.lower() else None
                })
                continue

            # Case-insensitive exact match (catches "Hash"→"hash", "CSV"→"csv")
            if token.lower() in known_lower:
                entities.append({
                    'original': token,
                    'matched': known_lower[token.lower()],
                    'confidence': 0.99,
                    'method': 'exact_ci',
                    'disambiguated': disambiguated if disambiguated != token.lower() else None
                })
                continue

            # Stemmed exact match (catches "hashing"→"hash", "scanning"→"scan")
            if stemmed in known_lower:
                entities.append({
                    'original': token,
                    'matched': known_lower[stemmed],
                    'confidence': 0.95,
                    'method': 'stem_exact',
                    'disambiguated': disambiguated if disambiguated != token.lower() else None
                })
                continue

            # Short tokens (<=4 chars): skip fuzzy — too noisy
            # But we already tried exact and stemmed above, so short tokens
            # like "hash", "scan", "port" will still match if they're entities
            if len(stemmed) <= 4:
                continue

            # Fuzzy match (Jaro-Winkler similarity) for 5+ char tokens
            best_match = None
            best_score = 0.0

            for entity in known_entities:
                e_lower = entity.lower()
                score = jellyfish.jaro_winkler_similarity(stemmed, e_lower)

                # Strong bonus for exact word match in multi-word entity
                if stemmed == e_lower or f" {stemmed} " in f" {e_lower} ":
                    score += 0.15

                # Bonus for same start
                if e_lower.startswith(stemmed[:3]): score += 0.1

                # Penalty for huge length difference
                len_diff = abs(len(stemmed) - len(entity))
                if len_diff > 8: score -= 0.15

                if score > best_score and score > 0.90:
                    best_score = score
                    best_match = entity

            if best_match:
                entities.append({
                    'original': token,
                    'matched': best_match,
                    'confidence': min(1.0, best_score),
                    'method': 'fuzzy',
                    'disambiguated': disambiguated if disambiguated != token.lower() else None
                })

        return entities

    def classify_intent(self, tokens: List[str], entities: List[Dict[str, Any]] = None,
                        raw_input: str = '') -> str:
        """Classify intent based on keyword combinations and entity context"""
        token_set = set(tokens)

        # Check for explicit /command prefixes first (highest priority)
        raw_stripped = raw_input.strip().lower()
        if raw_stripped.startswith('/debug'):
            return 'DEBUG'
        if raw_stripped.startswith('/learn') or raw_stripped.startswith('/teach'):
            return 'LEARN'
        if raw_stripped.startswith('/build') or raw_stripped.startswith('/make'):
            return 'BUILD'
        if raw_stripped.startswith('/chat') or raw_stripped.startswith('/explain'):
            return 'CHAT'
        if raw_stripped.startswith('/domain'):
            return 'DOMAIN'

        # Count keyword matches for each mode
        build_score = len(token_set & self.BUILD_KEYWORDS)
        chat_score = len(token_set & self.CHAT_KEYWORDS)
        debug_score = len(token_set & self.DEBUG_KEYWORDS)
        learn_score = len(token_set & self.LEARN_KEYWORDS)

        # Action verbs imply BUILD (e.g. "list files", "read csv", "download page")
        action_score = len(token_set & self.ACTION_VERBS)

        # DEBUG gets highest priority (most specific)
        if debug_score > 0:
            return 'DEBUG'

        # LEARN: only if learn keywords present AND no action verbs (otherwise
        # "learn to download files" would be LEARN instead of BUILD)
        if learn_score > 0 and build_score == 0 and action_score == 0:
            return 'LEARN'

        # Explicit BUILD keywords
        if build_score > 0:
            return 'BUILD'

        # Implicit BUILD: action verbs + entities that map to code operations
        if action_score > 0 and chat_score == 0:
            return 'BUILD'

        # Implicit BUILD: multiple code-related entities without question words
        if entities and len(entities) >= 2 and chat_score == 0:
            return 'BUILD'

        # CHAT only if explicit question words
        if chat_score > 0:
            return 'CHAT'

        # Default: if entities found, assume BUILD; otherwise CHAT
        if entities and len(entities) > 0:
            return 'BUILD'
        return 'CHAT'

    def extract_parameters(self, text: str, tokens: List[str]) -> Dict[str, Any]:
        """Extract parameters like paths, formats, numbers"""
        params = {}

        # File paths (absolute or relative)
        path_pattern = r'(?:~?/[\w/.-]+|\.{1,2}/[\w/.-]+|\w+/[\w/.-]+)'
        paths = re.findall(path_pattern, text)
        if paths:
            params['paths'] = paths
            params['input_path'] = paths[0]  # First path is input by default

        # File formats/extensions
        format_pattern = r'\b(\w+)\s+file'
        formats = re.findall(format_pattern, text, re.IGNORECASE)
        if formats:
            params['input_format'] = formats[0].upper()

        # Output formats (csv, json, txt, etc.)
        output_pattern = r'(?:to|into|as)\s+(\w+)'
        outputs = re.findall(output_pattern, text, re.IGNORECASE)
        if outputs:
            params['output_format'] = outputs[0].upper()

        # Numbers
        numbers = [t for t in tokens if t.isdigit()]
        if numbers:
            params['numbers'] = [int(n) for n in numbers]

        return params

    def _detect_composition(self, raw_input: str, tokens: List[str]) -> Dict[str, Any]:
        """Detect multi-step composition from conjunctions and action verbs.

        "download webpage and extract emails" → is_composition=True, sub_tasks=["download", "extract"]
        "read csv and convert to json" → is_composition=True, sub_tasks=["read", "convert"]
        """
        raw_lower = raw_input.lower()
        raw_words = raw_lower.split()

        # Check for conjunction + multiple action verbs
        has_conjunction = bool(set(raw_words) & self.COMPOSITION_CONJUNCTIONS)
        action_verbs_found = [t for t in tokens if t in self.ACTION_VERBS]

        is_composition = has_conjunction and len(action_verbs_found) >= 2

        # Also detect "X to Y" patterns (convert, transform)
        if not is_composition and len(action_verbs_found) >= 1:
            # "csv to json", "yaml to json" patterns
            if ' to ' in raw_lower or ' into ' in raw_lower:
                # Check if this is a conversion (action verb + "to" + format)
                conversion_verbs = {'convert', 'transform', 'export', 'read'}
                if set(action_verbs_found) & conversion_verbs:
                    is_composition = True

        return {
            'is_composition': is_composition,
            'sub_tasks': action_verbs_found if is_composition else [],
        }

    def parse(self, user_input: str) -> Dict[str, Any]:
        """
        Parse user input into structured intent

        Returns:
            {
                'mode': 'BUILD' | 'CHAT' | 'DEBUG' | 'LEARN',
                'raw': original input,
                'tokens': cleaned tokens,
                'entities': matched entities,
                'params': extracted parameters,
                'confidence': overall confidence,
                'requires_output': bool,
                'is_composition': bool,
                'sub_tasks': list of action verbs for composition
            }
        """
        # Step 1: Tokenize
        tokens = self.tokenize(user_input)

        # Step 2: Entity extraction
        entities = self.extract_entities(tokens)

        # Step 3: Intent classification (with entity context)
        mode = self.classify_intent(tokens, entities, raw_input=user_input)

        # Step 4: Parameter extraction
        params = self.extract_parameters(user_input, tokens)

        # Step 5: Detect output requirement
        requires_output = bool(set(tokens) & self.OUTPUT_TOKENS)

        # Step 6: Detect composition (multi-step tasks)
        composition = self._detect_composition(user_input, tokens)

        # Overall confidence (average of entity confidences)
        if entities:
            confidence = sum(e['confidence'] for e in entities) / len(entities)
        else:
            confidence = 0.5  # Low confidence if no entities matched

        return {
            'mode': mode,
            'raw': user_input,
            'tokens': tokens,
            'entities': entities,
            'params': params,
            'confidence': confidence,
            'requires_output': requires_output,
            'is_composition': composition['is_composition'],
            'sub_tasks': composition['sub_tasks'],
        }
