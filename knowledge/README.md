# Knowledge base

This directory is baked into the submission image and searched at run time by the
agent's `knowledge` tool (grep-based retrieval, offline). It is the offline
substitute for web search — which roughly doubles CTF solve rate in the research,
and which the run sandbox forbids.

## What to put here

- **Your `ctf-notes`** — the single highest-value content. Before building the
  image: `cp -r ../ctf-notes/* knowledge/` (or clone it in during the Docker
  build). Technique notes beat flag-spoiling writeups.
- Cheatsheets, command references, past-writeup method sections, tool recipes.
- Prefer `.md`/`.txt`/`.rst` (also searched: `.py`, `.sh`). One topic per file or
  clear headings help retrieval.

## How the agent uses it

Every specialist has a `knowledge` tool: it greps these files for the query's
keywords and returns the best-matching snippets as **reference** (never flag
evidence — an example `CTF{...}` in a writeup cannot be submitted as a real flag).

## Notes

- Keep it technique-focused. Example flags in writeups are harmless (wrong
  submissions carry no penalty) but add noise.
- Default search path in the image is `/opt/ctf-harness/knowledge`; override with
  `CTF_KNOWLEDGE_DIR`. Locally it falls back to `./knowledge`.
- Don't commit anything secret here — the submission is logged and reviewed.
