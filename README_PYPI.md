# O1-O — deterministic code synthesis operator

Zero-LLM program composition from natural-language intent.  
8-color algebraic type system · 7-pass causal inference · 7-layer verification · 9-phase autonomous engagement.

**~300ms generation · offline · air-gapped · deterministic**

```
pip install o1op
```

## Quick start

```bash
# interactive REPL
o1o

# or run from source
python3 -m o1o_o.o1o_live
```

## What it does

You type intent in plain English. O1-O queries a `.causal` knowledge graph (~75k triplets, ~1200 code fragments), assembles a working program, runs a 7-layer verification pipeline (compile check → formal verification → evasion scan → OPSEC audit), and hands you deployable code. No model, no API, no network.

```
O1-O> build a port scanner with banner grabbing for 10.0.0.1
```

11 pipeline steps, ~300ms, done.

## The `/engage` operator

Full autonomous engagement: recon → tool generation → deployment → post-exploitation → reporting. One command, zero human intervention.

```
O1-O> /engage 10.0.0.1
```

## What's inside

| Component | Count |
|---|---|
| `.causal` knowledge graph triplets | ~75,000 |
| Code fragments (verified) | ~1,200 |
| MITRE ATT&CK techniques covered | 102 |
| MITRE tactics covered | 14/14 |
| Algebraic type colors | 8 |
| Pipeline verification layers | 7 |

## Current state

This works. It generates real code from a real knowledge graph in real time. It's also the first public release and there are rough edges — some fragment selections are imprecise, some intents don't have matching fragments yet, and the engagement operator iterates on failures live (which is a feature, not a bug — you see it retry and adapt).

If something doesn't work, fix it. The fragment registry is plain JSON, the knowledge graph is documented, the pipeline is readable Python. PRs welcome, issues welcome, forks encouraged.

## Requirements

- Python ≥ 3.10
- Dependencies: `msgpack`, `jellyfish`, `requests`, `beautifulsoup4`

## Full documentation

Architecture, papers (9 peer-reviewed at 4 IEEE 2026 conferences + IBM z/OS mainframe validation), math, and the full technical deep-dive:

**→ [github.com/DT-Foss/O1-O](https://github.com/DT-Foss/O1-O)**

## License

Apache-2.0 · David Tom Foss · dtfoss-dev@proton.me
