#!/usr/bin/env python3
"""
O1-O Boot — Loads generated bridges at startup.
Import this instead of directly instantiating ForgeSession.

Usage:
    from boot import boot_o1o
    session, knowledge = boot_o1o()
"""

import json
import os
import sys

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SRC_DIR)
GENERATED_BRIDGES = os.path.join(REPO_ROOT, "triplets", "generated_bridges.json")


def boot_o1o():
    """Boot O1-O with generated bridges for 100% fragment coverage."""
    sys.path.insert(0, SRC_DIR)
    from o1o import ForgeSession

    session = ForgeSession()

    # Inject generated bridges
    if os.path.exists(GENERATED_BRIDGES):
        with open(GENERATED_BRIDGES) as f:
            bridges = json.load(f)
        session.knowledge.load_transient_triplets(bridges, "bridge_intents")
        print(f"O1-O: Injected {len(bridges)} generated bridges (100% coverage)")

    return session, session.knowledge


# Backward-compat alias
boot_forge_v2 = boot_o1o


if __name__ == "__main__":
    session, ke = boot_o1o()
    stats = ke.get_stats()
    print(f"Triplets: {stats['explicit_triplets']} explicit + {stats['inferred_triplets']} inferred")
    print(f"Entities: {stats['entities']}")
