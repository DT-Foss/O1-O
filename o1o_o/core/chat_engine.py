"""
Chat Engine — Answer questions via knowledge graph + template responses

Uses knowledge graph to answer questions:
1. Entity lookup (what is X?)
2. Triplet retrieval (how does X relate to Y?)
3. Problem-solution matching (X is slow → try Y)
4. Template-based response generation
5. Multi-entity comparison
6. Topic-aware recommendations

No LLM — just templates + entity insertion + graph traversal
"""
# Dependencies: none
# Depended by: none (leaf module)


from typing import Dict, Any, List, Optional


class ChatEngine:
    """Answer questions without LLM using knowledge graph and templates"""

    # Response templates by question type
    TEMPLATES = {
        'what_is': "{entity} is a {type} that {mechanism} {outcome}.",
        'how_to': "To {action} {entity}, you can use {library}: {example}",
        'why': "{entity} {mechanism} {outcome} because {reason}.",
        'when': "{entity} is used when {condition}.",
        'which': "For {entity}, consider: {options}",
        'compare': "Comparing {entity1} vs {entity2}: {comparison}",
        'fix': "To fix '{problem}', try: {solution}",
        'recommend': "For {task}, I recommend: {recommendations}",
        'default': "I found these facts about {entity}: {facts}",
    }

    # Problem pattern → friendly description
    PROBLEM_PATTERNS = {
        'slow': 'performance issue',
        'error': 'error handling',
        'crash': 'stability issue',
        'memory': 'memory management',
        'timeout': 'timeout/latency',
        'security': 'security concern',
        'broken': 'functionality issue',
        'missing': 'missing component',
    }

    def __init__(self, knowledge_engine):
        self.knowledge = knowledge_engine

    def answer(self, intent: Dict[str, Any]) -> str:
        """
        Generate answer from intent

        Routes to specialized answer methods based on question type.
        """
        entities = intent.get('entities', [])
        tokens = intent.get('tokens', [])
        raw = intent.get('raw', '').lower()

        if not entities and not tokens:
            return "I don't understand the question. Can you rephrase?"

        # Detect question type
        question_type = self.detect_question_type(tokens, raw)

        # Route to specialized handler
        if question_type == 'fix':
            return self._answer_fix(raw, entities, tokens)
        elif question_type == 'compare':
            return self._answer_compare(entities)
        elif question_type == 'recommend':
            return self._answer_recommend(raw, entities, tokens)
        elif question_type == 'how_to':
            return self._answer_howto(entities, tokens)
        elif question_type == 'what_is':
            return self._answer_what_is(entities)
        else:
            return self._answer_general(entities, question_type)

    def detect_question_type(self, tokens: List[str], raw: str = '') -> str:
        """Detect question type from tokens and raw text"""
        token_set = set(tokens)

        # Fix/solve/debug questions
        fix_markers = {'fix', 'solve', 'resolve', 'debug', 'repair', 'why', 'broken', 'error', 'crash'}
        if token_set & fix_markers:
            return 'fix'

        # Comparison
        compare_markers = {'vs', 'versus', 'compare', 'difference', 'between', 'better', 'which'}
        if token_set & compare_markers:
            return 'compare'

        # Recommendation
        recommend_markers = {'recommend', 'suggest', 'best', 'should', 'use', 'choose', 'pick'}
        if token_set & recommend_markers:
            return 'recommend'

        # Question words
        if 'what' in token_set:
            return 'what_is'
        elif 'how' in token_set:
            return 'how_to'
        elif 'why' in token_set:
            return 'why'
        elif 'when' in token_set:
            return 'when'
        elif 'which' in token_set:
            return 'which'

        return 'default'

    def _answer_fix(self, raw: str, entities: List[Dict], tokens: List[str]) -> str:
        """Answer problem-fixing questions using problem_solution triplets"""
        # Search for problem patterns in the query
        problem_text = raw

        # Try direct entity lookup
        for entity in entities:
            name = entity['matched']
            results = self.knowledge.query_entity(name)

            for r in results:
                t = r['triplet']
                if t['mechanism'] in ('solved_by', 'fixed_by', 'remedied_by'):
                    return self.TEMPLATES['fix'].format(
                        problem=t['trigger'],
                        solution=t['outcome']
                    )

        # Fuzzy search through all triplets for "solved_by" patterns
        solutions = []
        for t in self.knowledge.all_triplets:
            if t.get('mechanism') != 'solved_by':
                continue
            trigger = t['trigger'].lower()
            # Check if any token from the query appears in the trigger
            if any(tok in trigger for tok in tokens if len(tok) > 3):
                solutions.append(t)

        if solutions:
            # Sort by confidence
            solutions.sort(key=lambda x: x.get('confidence', 0.5), reverse=True)
            best = solutions[:3]
            advice = []
            for s in best:
                advice.append(f"  - {s['trigger']} -> {s['outcome']} (confidence: {s.get('confidence', 0.5):.0%})")
            return f"Possible solutions:\n" + "\n".join(advice)

        # Check for general problem patterns
        for pattern, desc in self.PROBLEM_PATTERNS.items():
            if pattern in raw:
                return (f"This looks like a {desc}. "
                       f"Use /build to generate a fix, or try: /debug <your error message>")

        return "I couldn't find a specific fix. Try describing the error message, or use /debug mode."

    def _answer_compare(self, entities: List[Dict]) -> str:
        """Compare two entities using knowledge graph"""
        if len(entities) < 2:
            return "I need at least two things to compare. Example: 'compare flask vs django'"

        e1 = entities[0]['matched']
        e2 = entities[1]['matched']

        results1 = self.knowledge.query_entity(e1)
        results2 = self.knowledge.query_entity(e2)

        if not results1 and not results2:
            return f"I don't have enough knowledge about '{e1}' or '{e2}' to compare them."

        # Build feature sets
        features1 = set()
        features2 = set()

        for r in results1:
            features1.add(r['triplet']['outcome'])
        for r in results2:
            features2.add(r['triplet']['outcome'])

        shared = features1 & features2
        only1 = features1 - features2
        only2 = features2 - features1

        lines = [f"**{e1} vs {e2}:**"]
        if shared:
            lines.append(f"  Both: {', '.join(list(shared)[:5])}")
        if only1:
            lines.append(f"  Only {e1}: {', '.join(list(only1)[:5])}")
        if only2:
            lines.append(f"  Only {e2}: {', '.join(list(only2)[:5])}")

        if not shared and not only1 and not only2:
            lines.append("  No direct comparison data available.")

        return "\n".join(lines)

    def _answer_recommend(self, raw: str, entities: List[Dict], tokens: List[str]) -> str:
        """Give recommendations based on knowledge graph"""
        recommendations = []

        for entity in entities:
            name = entity['matched']
            results = self.knowledge.query_entity(name)

            for r in results:
                t = r['triplet']
                if t['mechanism'] in ('uses', 'library_for', 'tool_for', 'solved_by'):
                    recommendations.append({
                        'tool': t['outcome'],
                        'for': t['trigger'],
                        'confidence': t.get('confidence', 0.5),
                    })

        if recommendations:
            # Sort by confidence, deduplicate
            seen = set()
            unique = []
            for rec in sorted(recommendations, key=lambda x: x['confidence'], reverse=True):
                if rec['tool'] not in seen:
                    seen.add(rec['tool'])
                    unique.append(rec)

            lines = ["Recommendations:"]
            for rec in unique[:5]:
                lines.append(f"  - {rec['tool']} for {rec['for']} ({rec['confidence']:.0%})")
            return "\n".join(lines)

        return "I don't have specific recommendations. Try being more specific about what you need."

    def _answer_howto(self, entities: List[Dict], tokens: List[str]) -> str:
        """Answer how-to questions"""
        for entity in entities:
            name = entity['matched']
            results = self.knowledge.query_entity(name)

            for r in results:
                t = r['triplet']
                if t['mechanism'] in ('uses', 'library_for', 'implemented_by'):
                    return f"To work with {name}, use {t['outcome']}."

            # Check for bridge triplets (direct code generation paths)
            if hasattr(self.knowledge, '_bridge_lookup'):
                bridge_result = self.knowledge._bridge_lookup(name)
                if bridge_result:
                    fragments = bridge_result.get('fragments', [])
                    if fragments:
                        return (f"I can generate code for '{name}' using: {', '.join(fragments)}. "
                               f"Use /build to generate it.")

        if entities:
            return f"I know about '{entities[0]['matched']}' but don't have how-to instructions. Try /build instead."

        return "I need to know what you want to do. Example: 'how to read csv file'"

    def _answer_what_is(self, entities: List[Dict]) -> str:
        """Answer what-is questions"""
        if not entities:
            return "What would you like to know about?"

        main_entity = entities[0]['matched']
        results = self.knowledge.query_entity(main_entity)

        if not results:
            return (f"I don't have knowledge about '{main_entity}'. "
                   f"Would you like to teach me? (use /learn mode)")

        # Find type/category triplet
        for r in results:
            t = r['triplet']
            if t['mechanism'] in ('is', 'type_of', 'category'):
                return self.TEMPLATES['what_is'].format(
                    entity=main_entity,
                    type=t['outcome'],
                    mechanism='does',
                    outcome='various operations'
                )

        # Fallback: list what it does
        mechanisms = [r['triplet']['mechanism'] for r in results[:5]]
        outcomes = [r['triplet']['outcome'] for r in results[:5]]

        facts = [f"{m} → {o}" for m, o in zip(mechanisms, outcomes)]
        return f"{main_entity}: {'; '.join(facts)}"

    def _answer_general(self, entities: List[Dict], question_type: str) -> str:
        """General answer using knowledge graph"""
        if not entities:
            return "Can you be more specific? I work best with entity names like modules, functions, or tools."

        main_entity = entities[0]['matched']
        results = self.knowledge.query_entity(main_entity)

        if not results:
            return (f"I don't have knowledge about '{main_entity}'. "
                   f"Would you like to teach me? (use /learn)")

        # Default: list facts
        facts = []
        for r in results[:5]:
            t = r['triplet']
            facts.append(f"{t['trigger']} {t['mechanism']} {t['outcome']}")

        return self.TEMPLATES['default'].format(
            entity=main_entity,
            facts='; '.join(facts)
        )
