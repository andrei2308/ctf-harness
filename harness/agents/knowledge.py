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
_TEXT_SUFFIXES = {".md", ".txt", ".rst", ".adoc", ".org", ".py", ".sh", ".sol", ".asm"}
_DOC_SUFFIXES = {".md", ".txt", ".rst", ".adoc", ".org"}

# Specialist -> how its notes are named. A file belongs to a category when any
# component of its path (directory or file name) starts with one of these, which
# fits the ctf-notes layout: `pwn_notes/`, `crypto/`, `forensics_notes.md`, ...
_CATEGORY_PATHS: dict[str, tuple[str, ...]] = {
    "rev": ("rev",),
    "pwn": ("pwn", "privesc"),
    "crypto": ("crypto", "cracking"),
    "forensics": ("forensic", "steg", "network"),
    "web": ("web",),
    "mobile": ("mobile",),
    "blockchain": ("blockchain",),
    "pyjail": ("pyjail", "jail"),
}
_STOPWORDS = {
    "this", "that", "with", "from", "have", "your", "what", "find", "flag", "will",
    "file", "files", "challenge", "category", "description", "service", "target",
    "they", "there", "here", "into", "some", "just", "been", "were", "them", "then",
    "about", "which", "when", "where", "should", "could", "would", "please", "given",
    "know", "need", "does", "make", "like", "more", "only", "also", "very", "tool",
}
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


def _headings(lines: list[str]) -> list[tuple[int, int, str]]:
    """(line index, level, title) for markdown headings, skipping fenced code —
    notes are full of `# comment` lines inside code blocks."""
    out, fenced = [], False
    for i, ln in enumerate(lines):
        st = ln.lstrip()
        if st.startswith("```") or st.startswith("~~~"):
            fenced = not fenced
            continue
        if fenced:
            continue
        m = re.match(r"(#{1,3})\s+(.+?)\s*#*\s*$", ln)
        if m:
            out.append((i, len(m.group(1)), m.group(2).strip()))
    return out


def _category_files(base: Path, category: str) -> list[Path]:
    keys = _CATEGORY_PATHS.get(category)
    files = []
    for p in _iter_files(base):
        rel = p.relative_to(base)
        if len(rel.parts) == 1 and rel.name.lower() == "readme.md":
            continue                       # the knowledge base's own readme
        parts = [x.lower() for x in rel.parts]
        if keys is None or any(part.startswith(key) for part in parts for key in keys):
            files.append(p)
    # Playbooks and decision guides first: they route to everything else.
    files.sort(key=lambda p: (not re.search(r"playbook|decision|cheatsheet", p.name, re.I),
                              str(p)))
    return files


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _suggest(base: Path, files: list[Path], hint: str, top: int = 3) -> list[str]:
    """Sections whose text shares at least two distinct keywords with the
    challenge text (or one, in the heading). Returned as `path § heading`."""
    terms = {t for t in re.findall(r"[a-z0-9_]{4,}", hint.lower())} - _STOPWORDS
    if not terms:
        return []
    scored: list[tuple[int, str]] = []
    for path in files:
        if path.suffix.lower() not in _DOC_SUFFIXES:
            continue
        lines = _read_lines(path)
        heads = _headings(lines)
        for n, (start, _lvl, title) in enumerate(heads):
            end = heads[n + 1][0] if n + 1 < len(heads) else len(lines)
            body = "\n".join(lines[start:end]).lower()
            hits = {t for t in terms if t in body}
            in_title = {t for t in terms if t in title.lower()}
            if len(hits) >= 2 or in_title:
                scored.append((len(hits) + 3 * len(in_title),
                               f"{path.relative_to(base)} § {title}"))
    scored.sort(key=lambda x: -x[0])
    return [label for _, label in scored[:top]]


def primer(category: str, hint: str = "", max_chars: int = 2500) -> str:
    """A short index of the notes for this specialist, for the task prompt: which
    files exist and what their sections cover, so the model opens the right note
    instead of guessing search terms. Costs no model call. Returns "" when there
    is no knowledge base, nothing relevant, or max_chars is 0."""
    base = knowledge_dir()
    if base is None or max_chars <= 0:
        return ""
    files = _category_files(base, category)
    if not files:
        return ""
    head = (f"Offline notes for this category (knowledge base: {base.resolve()}). Open "
            'one with the `knowledge` tool, e.g. {"path": "<file>", "section": '
            '"<heading>"}, or search with {"query": "..."}. Listed scripts can be run '
            "from `shell` by their path under the knowledge base.")
    out = [head]
    used = len(head)
    matches = _suggest(base, files, hint)
    if matches:
        line = "Likely relevant to this challenge: " + "; ".join(matches)
        out.append(line)
        used += len(line)
    for n, path in enumerate(files):
        rel = path.relative_to(base)
        if path.suffix.lower() in _DOC_SUFFIXES:
            titles = [t for _, lvl, t in _headings(_read_lines(path)) if lvl <= 2][:8]
            line = f"- {rel}" + (": " + "; ".join(t[:48] for t in titles) if titles else "")
        else:
            line = f"- {rel} (script)"
        if used + len(line) > max_chars:
            out.append(f"- … and {len(files) - n} more (search with `knowledge`)")
            break
        out.append(line)
        used += len(line) + 1
    return "\n".join(out)


def read_note(base: Path, rel_path: str, section: str = "") -> str:
    """One note, or one section of it. Confined to the knowledge base."""
    target = (base / rel_path.lstrip("/")).resolve()
    try:
        target.relative_to(base.resolve())
    except ValueError:
        return "(path is outside the knowledge base)"
    if not target.is_file():
        return f"(no such note: {rel_path})"
    lines = _read_lines(target)
    heads = _headings(lines)
    toc = "; ".join(t for _, lvl, t in heads if lvl <= 2)
    if section:
        want = section.strip().lower()
        for n, (start, lvl, title) in enumerate(heads):
            if want in title.lower():
                end = len(lines)
                for nxt_start, nxt_lvl, _t in heads[n + 1:]:
                    if nxt_lvl <= lvl:
                        end = nxt_start
                        break
                return "\n".join(lines[start:end])[:_MAX_OUTPUT]
        return f"(no section matching {section!r}; sections: {toc})"
    text = "\n".join(lines)
    if len(text) > _MAX_OUTPUT:
        text = (text[:_MAX_OUTPUT]
                + f"\n…[cut; pass `section` to read one of: {toc}]")
    return text


class KnowledgeSearchTool(Tool):
    name = "knowledge"
    description = (
        "Search the offline knowledge base (your CTF notes, cheatsheets, past "
        "writeups) for techniques and commands relevant to this challenge. Use it "
        "when you recognise a challenge type and want the known approach. Returns "
        "REFERENCE snippets, not flag evidence — the real flag must still come "
        "from the challenge's own output. Give `query` to search, or `path` "
        "(optionally with `section`) to read a note listed in your task.")

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "query": {"type": "string",
                      "description": "keywords, e.g. 'house of force tcache' or 'flask session forge'"},
            "path": {"type": "string",
                     "description": "a note to read, relative to the knowledge base"},
            "section": {"type": "string",
                        "description": "with `path`: a heading (substring) to read just that section"},
            "max_results": {"type": "integer"},
        }}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = knowledge_dir()
        if base is None:
            return ToolResult(self.name, b"", "knowledge:none", is_evidence=False,
                              error="no knowledge base configured (set CTF_KNOWLEDGE_DIR)")
        path = str(args.get("path", "")).strip()
        if path:
            text = read_note(base, path, str(args.get("section", "")).strip())
            return ToolResult(self.name, text.encode("utf-8"), f"knowledge:{path[:40]}",
                              is_evidence=False)
        query = str(args.get("query", "")).strip()
        if not query:
            return ToolResult(self.name, b"", "knowledge:empty", is_evidence=False,
                              error="query or path required")
        try:
            n = int(args.get("max_results") or 5)
        except (TypeError, ValueError):
            n = 5
        result = search_knowledge(base, query, max_results=max(1, min(n, 10)))
        # is_evidence=False: a flag-looking string in a writeup must not ground.
        return ToolResult(self.name, result.encode("utf-8"), f"knowledge:{query[:40]}",
                          is_evidence=False)
