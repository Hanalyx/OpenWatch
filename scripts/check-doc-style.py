#!/usr/bin/env python3
"""Hanalyx documentation style check (language-neutral: runs anywhere python3 is present).

Enforces the prohibited list from the developer documentation style guide (canonical copy:
Context Plane dev/DEVELOPER_DOCUMENTATION_STYLE_GUIDE):

  1. Em dashes (the U+2014 character).
  2. Emojis / decorative pictographs.
  3. AI-speak filler and hype words and phrases.

Fenced code blocks and inline `code` spans are exempt (code is not prose). A line containing
`<!-- doc-style: allow -->` is skipped when a maintainer has cleared the term.

Usage:
  python3 scripts/check-doc-style.py <file.md> [more.md ...]   # check specific files
  python3 scripts/check-doc-style.py --changed                 # markdown changed vs origin/main
  python3 scripts/check-doc-style.py --all                     # all tracked *.md
"""
import re
import subprocess
import sys

AI_SPEAK = [
    "seamless", "robust", "powerful", "cutting-edge", "best-in-class", "world-class",
    "state-of-the-art", "revolutionary", "game-changing", "game-changer", "next-generation",
    "enterprise-grade", "blazing-fast", "blazing fast",
    "leverage", "utilize", "facilitate", "empower", "unlock", "elevate", "delve", "embark",
    "foster", "harness", "supercharge",
    "it's important to note", "it is important to note", "it's worth mentioning",
    "needless to say", "at the end of the day", "in today's fast-paced world",
    "in the ever-evolving", "rest assured", "peace of mind", "let's dive in", "dive in",
    "in conclusion", "as an ai", "game changer",
]
# Single tokens match on word boundaries; multiword phrases match as substrings.
AI_RE = [
    (t, re.compile((r"\b" + re.escape(t) + r"\b") if " " not in t else re.escape(t), re.I))
    for t in AI_SPEAK
]
EM_DASH = re.compile("—")
# python3's re has no \p{Extended_Pictographic}; approximate with the common emoji blocks.
EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U00002B00-\U00002BFF"
    "\U0001F1E6-\U0001F1FF\U0000FE00-\U0000FE0F]"
)
INLINE_CODE = re.compile(r"`[^`]*`")
FENCE = re.compile(r"^\s*```")
ALLOW = re.compile(r"<!--\s*doc-style:\s*allow\s*-->")


def git(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.strip()
    except Exception:
        return ""


def resolve_files(argv):
    flags = {a for a in argv if a.startswith("--")}
    explicit = [a for a in argv if not a.startswith("--") and a.endswith(".md")]
    if explicit:
        return explicit
    if "--all" in flags:
        return [f for f in git(["git", "ls-files", "*.md"]).splitlines() if f]
    base = git(["git", "merge-base", "origin/main", "HEAD"]) or "origin/main"
    changed = git(["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD", "--", "*.md"])
    if not changed:
        changed = git(["git", "diff", "--name-only", "--cached", "--", "*.md"])
    return [f for f in changed.splitlines() if f]


def main():
    files = resolve_files(sys.argv[1:])
    if not files:
        print("doc-style: no markdown to check")
        return 0

    findings = 0
    for path in files:
        try:
            with open(path, encoding="utf-8") as fh:
                lines = fh.read().split("\n")
        except OSError:
            continue
        in_fence = False
        for n, raw in enumerate(lines, 1):
            if FENCE.match(raw):
                in_fence = not in_fence
                continue
            if in_fence or ALLOW.search(raw):
                continue
            line = INLINE_CODE.sub("", raw)

            def hit(label, token):
                nonlocal findings
                findings += 1
                sys.stderr.write(f"  {path}:{n}  {label}: {token!r}\n")

            if EM_DASH.search(line):
                hit("em-dash", "—")
            m = EMOJI.search(line)
            if m:
                hit("emoji", m.group(0))
            for term, rx in AI_RE:
                mm = rx.search(line)
                if mm:
                    hit("ai-speak", mm.group(0))
                    break

    if findings:
        sys.stderr.write(
            f"\ndoc-style FAILED: {findings} finding(s). "
            "See dev/DEVELOPER_DOCUMENTATION_STYLE_GUIDE.\n"
            "Fix the prose, or add `<!-- doc-style: allow -->` to a line a maintainer has cleared.\n"
        )
        return 1
    print(f"doc-style: {len(files)} file(s) clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
