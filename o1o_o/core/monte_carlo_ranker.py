"""
Monte Carlo Candidate Ranker — Generate & rank multiple code candidates

For each task, generate N candidate code samples (different fragment paths),
execute all in parallel, and select the highest-scoring candidate.

Scoring: success(+10) + has_output(+3) + no_stderr(+2) = max 15 points
"""
# Dependencies: none
# Depended by: self_improvement_turbo


from typing import Dict, List, Tuple, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import json
from pathlib import Path


class MonteCarloRanker:
    """Generate multiple candidates and rank them"""

    def __init__(self, executor, code_assembler, knowledge):
        """
        Args:
            executor: ForgeSession.executor
            code_assembler: ForgeSession.code_assembler
            knowledge: ForgeSession.knowledge
        """
        self.executor = executor
        self.code_assembler = code_assembler
        self.knowledge = knowledge
        self.max_workers = 3  # Parallel candidates
        self.num_candidates = 3  # Generate N alternatives

    def generate_candidates(self, intent: Dict[str, Any]) -> List[str]:
        """Generate multiple code candidate paths"""
        candidates = []

        # Get inference chains upfront
        chains = self.knowledge.infer(intent, top_k=5)

        # Path 1: Original assembly (top chain)
        if chains:
            code1 = self.code_assembler.assemble(chains[0], intent)
            if code1 and "No implementation" not in code1:
                candidates.append(code1)

        # Path 2: Architecture-aware assembly
        code2 = self.code_assembler.assemble_v4_architecture_aware(intent)
        if code2 and code2 not in candidates and "No implementation" not in code2:
            candidates.append(code2)

        # Path 3+: Alternative chains
        for chain in chains[1:]:
            code = self.code_assembler.assemble(chain, intent)
            if code and "No implementation" not in code and code not in candidates:
                candidates.append(code)
                if len(candidates) >= self.num_candidates:
                    break

        # Fallback: at least one candidate
        if not candidates:
            candidates.append("print('error: no implementation')")

        return candidates[:self.num_candidates]

    def score_result(self, result: Dict[str, Any]) -> int:
        """Score execution result. Max 15 points."""
        score = 0

        # Success: +10
        if result.get('success'):
            score += 10
        # Failed but has output: +5
        elif result.get('stdout', '').strip():
            score += 5

        # Has output: +3
        if result.get('stdout', '').strip():
            score += 3

        # No stderr: +2
        if not result.get('stderr', '').strip():
            score += 2

        return score

    def rank_candidates(
        self,
        candidates: List[str],
        intent: Dict[str, Any],
        timeout: int = 10
    ) -> Tuple[str, int, List[Tuple[str, int, Dict]]]:
        """
        Execute all candidates in parallel and rank them.

        Returns:
            (best_code, best_score, all_results)
            where all_results = [(code, score, result), ...]
        """
        results = []

        # Execute in parallel
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(candidates))) as executor:
            futures = {
                executor.submit(self.executor.run, code, intent, timeout=timeout): code
                for code in candidates
            }

            for future in as_completed(futures):
                code = futures[future]
                try:
                    result = future.result()
                    score = self.score_result(result)
                    results.append((code, score, result))
                except Exception as e:
                    # Execution failed
                    result = {'success': False, 'error': str(e), 'stderr': str(e)}
                    results.append((code, 0, result))

        # Sort by score (highest first)
        results.sort(key=lambda x: x[1], reverse=True)

        if results:
            best_code, best_score, best_result = results[0]
            return best_code, best_score, results
        else:
            return "", 0, results

    def select_best(
        self,
        intent: Dict[str, Any],
        timeout: int = 10
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Main entry point: generate candidates, rank them, return best.

        Returns:
            (best_code, ranking_metadata)
        """
        # Generate candidates
        candidates = self.generate_candidates(intent)

        if not candidates:
            return "", {'candidates_count': 0, 'best_score': 0}

        # Rank in parallel
        best_code, best_score, all_results = self.rank_candidates(candidates, intent, timeout)

        # Metadata for logging/learning
        metadata = {
            'candidates_count': len(candidates),
            'best_score': best_score,
            'all_scores': [score for _, score, _ in all_results],
            'score_distribution': {
                'success_10': sum(1 for _, score, result in all_results if result.get('success')),
                'has_output_3': sum(1 for _, score, result in all_results if result.get('stdout', '').strip()),
                'no_stderr_2': sum(1 for _, score, result in all_results if not result.get('stderr', '').strip()),
            },
        }

        return best_code, metadata
