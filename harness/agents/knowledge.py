"""Offline knowledge base + retrieval tool.

Giving a CTF agent web access roughly doubles its solve rate (CTFusion, 2026),
and writeup/knowledge retrieval is the biggest non-model lever (CRAKEN). We have
no internet, so we bake a knowledge base INTO the submission image — Andrei's
`ctf-notes`, cheatsheets, curated writeups — and give every specialist a
`knowledge` tool that greps it for techniques relevant to the challenge in hand.

Retrieval is keyword/grep based: dependency-free, deterministic, offline, and
costs no model tokens to build an index. (Embeddings can be layered on later.)

CRITICAL: knowledge output is REFERENCE, never flag evidence. The tool returns
`is_evidence=False` so an example `CTF{...}` in a writeup can never ground/submit
as a real flag. (The real flag must still come from the challenge's own output.)
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .tools import Tool, ToolContext, ToolResult

# Where the knowledge base lives, in priority order. The image bakes it at
# /opt/ctf-harness/knowledge; locally it's ./knowledge in the repo.
_DEFAULT_DIRS = ["/opt/ctf-harness/knowledge", "knowledge"]
_TEXT_SUFFIXES = {".md", ".txt", ".rst", ".adoc", ".org", ".py", ".sh"}
_MAX_FILES = 2000
_MAX_OUTPUT = 12 * 1024          # bytes returned to the model
_SNIPPET_CONTEXT = 6             # lines of context around a match cluster


def knowledge_dir() -> Path | None:
    env = os.environ.get("CTF_KNOWLEDGE_DIR")
    candidates = ([env] if env else []) + _DEFAULT_DIRS
    for c in candidates:
        if c and Path(c).is_dir():
            return Path(c)
    return None


def _iter_files(base: Path):
    n = 0
    for p in sorted(base.rglob("*")):
        if p.is_file() and p.suffix.lower() in _TEXT_SUFFIXES and ".git" not in p.parts:
            yield p
            n += 1
            if n >= _MAX_FILES:
                return


def search_knowledge(base: Path, query: str, max_results: int = 5) -> str:
    """Return the most relevant snippets for `query` across the knowledge base."""
    terms = [t for t in re.split(r"\s+", query.strip()) if t]
    if not terms:
        return "(empty query)"
    patterns = [re.compile(re.escape(t), re.I) for t in terms]

    scored: list[tuple[int, Path, list[int]]] = []
    for path in _iter_files(base):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        hits = [i for i, ln in enumerate(lines)
                if any(p.search(ln) for p in patterns)]
        if hits:
            # score: matching lines, weighted by how many distinct terms appear.
            distinct = sum(1 for p in patterns if any(p.search(lines[i]) for i in hits))
            scored.append((len(hits) + 5 * distinct, path, hits))

    if not scored:
        return f"No knowledge-base entries matched: {query!r}"
    scored.sort(key=lambda t: -t[0])

    out: list[str] = []
    size = 0
    for _, path, hits in scored[:max_results]:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        lo = max(0, hits[0] - _SNIPPET_CONTEXT)
        hi = min(len(lines), hits[0] + _SNIPPET_CONTEXT * 3)
        snippet = "\n".join(lines[lo:hi])
        block = f"### {path} (lines {lo + 1}-{hi})\n{snippet}\n"
        if size + len(block) > _MAX_OUTPUT:
            break
        out.append(block)
        size += len(block)
    return "\n".join(out)


class KnowledgeSearchTool(Tool):
    name = "knowledge"
    description = (
        "Search the offline knowledge base (your CTF notes, cheatsheets, past "
        "writeups) for techniques and commands relevant to this challenge. Use it "
        "when you recognise a challenge type and want the known approach. Returns "
        "REFERENCE snippets, not flag evidence — the real flag must still come "
        "from the challenge's own output.")

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "query": {"type": "string",
                      "description": "keywords, e.g. 'house of force tcache' or 'flask session forge'"},
            "max_results": {"type": "integer"},
        }, "required": ["query"]}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = knowledge_dir()
        if base is None:
            return ToolResult(self.name, b"", "knowledge:none", is_evidence=False,
                              error="no knowledge base configured (set CTF_KNOWLEDGE_DIR)")
        query = str(args.get("query", "")).strip()
        if not query:
            return ToolResult(self.name, b"", "knowledge:empty", is_evidence=False,
                              error="query required")
        try:
            n = int(args.get("max_results") or 5)
        except (TypeError, ValueError):
            n = 5
        result = search_knowledge(base, query, max_results=max(1, min(n, 10)))
        # is_evidence=False: a flag-looking string in a writeup must not ground.
        return ToolResult(self.name, result.encode("utf-8"), f"knowledge:{query[:40]}",
                          is_evidence=False)
