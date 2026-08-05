#!/usr/bin/env python3
"""Hanalyx documentation style check (language-neutral: runs anywhere python3 is present).

Enforces the prohibited list from the developer documentation style guide (canonical copy:
Context Plane dev/DEVELOPER_DOCUMENTATION_STYLE_GUIDE):

  1. Em dashes (the U+2014 character).            markdown prose
  2. AI-speak filler and hype words and phrases.  markdown prose + code comments
  3. Emojis / decorative pictographs.             markdown AND structured files
  4. British spelling.                            markdown prose + code comments
  5. Reading level (Flesch-Kincaid grade).        markdown, per FILE

Scope. Em dashes are a prose rule and run on Markdown only. The emoji rule is not a prose rule,
so it also runs on structured files (.yml, .yaml, .json). AI speak and British spelling are
writing rules rather than document rules, so they also run on COMMENTS in .go, .ts, .tsx and .py,
per the guide's statement that US English binds "code comments, commit messages, and pull request
text". Reading level is computed per file over Markdown prose only.

Matching (HP-003).
- Single always-hype words match their inflected forms (leverage / leverages / leveraging /
  streamlined), so the common half of AI speak no longer escapes the check.
- Words that also have a legitimate technical sense (harness, unlock, elevate, delve, embark)
  are matched only inside their hype phrase, never as a bare word, so "test harness",
  "unlock_time", and "elevated privileges" are not flagged.
- Fenced code blocks and inline `code` spans in Markdown are exempt (code is not prose).
- A line with `<!-- doc-style: allow -->` (or `doc-style: allow` in a code comment) is skipped
  when a maintainer has cleared the term.

Reading level. Grade 10 is the WRITING TARGET; the gate sits above it, because prose can be dense
without being unclear. The gate was set by measuring this repository's own corpus, per the guide:
setting it above the observed maximum would prove only that the check ran. Files with fewer than
MIN_SENTENCES scored sentences are not scored, because Flesch-Kincaid is unstable on short text.
EXEMPT is a ratcheting ledger: entries may be removed by rewriting prose, never added to raise a
number, and the gate itself may only go down.

Usage:
  python3 scripts/check-doc-style.py <file> [more ...]   # check specific files
  python3 scripts/check-doc-style.py --changed           # files changed vs origin/main
  python3 scripts/check-doc-style.py --all               # all tracked files
  python3 scripts/check-doc-style.py --measure           # report grade levels, set no gate
  python3 scripts/check-doc-style.py --version           # print version and self sha256
  python3 scripts/check-doc-style.py --selftest          # run built-in matching tests
"""
import hashlib
import re
import subprocess
import sys

VERSION = "3"

# Single always-hype words, matched with their inflected forms (verbs and adjectives).
HYPE_WORDS = [
    "leverage", "utilize", "facilitate", "empower", "supercharge", "streamline",
    "seamless", "robust", "powerful", "revolutionary",
]

# Multiword and hyphenated hype terms, filler openers, model tells, and the hype PHRASES for the
# words that also have a legitimate technical sense (harness, unlock, elevate, delve, embark).
# Matched as substrings, case-insensitively.
HYPE_PHRASES = [
    "cutting-edge", "best-in-class", "world-class", "state-of-the-art",
    "game-changing", "game-changer", "game changer", "next-generation", "next generation",
    "enterprise-grade", "blazing-fast", "blazing fast",
    "needless to say", "at the end of the day", "in today's fast-paced world",
    "in the ever-evolving", "rest assured", "peace of mind", "dive in",
    "in conclusion", "as an ai", "great question", "certainly!",
    "you're all set", "you are all set", "we've got you covered", "we have got you covered",
    "harness the", "harnessing the", "harnesses the",
    "elevate your", "elevates your",
    "unlock the potential", "unlock the power", "unlocks the potential",
    "delve into", "embark on",
]

# Contraction pairs written once as a regex. The guide tells writers to use contractions, so the
# uncontracted form is the one that slips through when only the contracted form is listed.
CONTRACTION_RES = [
    re.compile(r"it(?:'s| is) important to note", re.I),
    re.compile(r"it(?:'s| is) worth mentioning", re.I),
]

# British to US spelling. Keys are matched with word boundaries and common inflections; the value
# is the US form to report. Deliberately narrow: only pairs where the British form has no separate
# US meaning. "modeling" is here; "modeling" is not ambiguous. Words whose British form is also a
# valid US word with a DIFFERENT meaning are excluded rather than risk a wrong autocorrect
# suggestion. Collisions created by INFLECTION are handled by NARROW below.
BRITISH_US = {
    "behaviour": "behavior", "favour": "favor", "honour": "honor", "labour": "labor",
    "colour": "color", "flavour": "flavor", "neighbour": "neighbor", "rumour": "rumor",
    "summarise": "summarize", "generalise": "generalize", "recognise": "recognize",
    "organise": "organize", "normalise": "normalize", "serialise": "serialize",
    "initialise": "initialize", "authorise": "authorize", "prioritise": "prioritize",
    "customise": "customize", "optimise": "optimize", "synchronise": "synchronize",
    "analyse": "analyze", "paralyse": "paralyze", "catalogue": "catalog",
    "centre": "center", "metre": "meter", "litre": "liter", "theatre": "theater",
    "defence": "defense", "offence": "offense", "pretence": "pretense",
    "judgement": "judgment", "acknowledgement": "acknowledgment",
    "modelled": "modeled", "modelling": "modeling", "cancelled": "canceled",
    "cancelling": "canceling", "labelled": "labeled", "labelling": "labeling",
    "signalled": "signaled", "travelled": "traveled", "fuelled": "fueled",
    "whilst": "while", "amongst": "among", "learnt": "learned", "spelt": "spelled",
    "grey": "gray", "artefact": "artifact",
    "sceptical": "skeptical", "licence": "license", "practise": "practice",
}
# Entries whose generic inflections would collide with a correct US word need their own pattern.
# "program" is the only one: program + d is "programmed", which is the US past tense of
# "program" and must not be flagged. Only the noun forms are British.
NARROW = {"programme": ("program", re.compile(r"\bprogrammes?\b", re.I))}
# Inflections that keep the British stem, so the plural and past forms are caught too.
# doc-style: allow -- this table names British spellings by definition.
BRITISH_RES = [
    (b, us, re.compile(rf"\b{re.escape(b)}(?:s|d|rs|ment|ments)?\b", re.I))
    for b, us in BRITISH_US.items()
] + [(b, us, rx) for b, (us, rx) in NARROW.items()]


def word_re(w):
    """Match a hype word and its common inflections, handling a silent trailing e."""
    if w.endswith("e"):
        return re.compile(rf"\b{re.escape(w[:-1])}(?:e|es|ed|ing)\b", re.I)
    return re.compile(rf"\b{re.escape(w)}(?:s|es|ed|ing|ly)?\b", re.I)


WORD_RES = [(w, word_re(w)) for w in HYPE_WORDS]
PHRASE_RES = [(p, re.compile(re.escape(p), re.I)) for p in HYPE_PHRASES]

EM_DASH = re.compile("—")
EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U00002B00-\U00002BFF"
    "\U0001F1E6-\U0001F1FF\U0000FE00-\U0000FE0F]"
)
INLINE_CODE = re.compile(r"`[^`]*`")
FENCE = re.compile(r"^\s*```")
ALLOW = re.compile(r"(?:<!--\s*)?doc-style:\s*allow")
# Link targets and bare URLs are stripped before spelling and reading level, so a third-party URL
# containing a British spelling, or a long path, never counts.
MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
BARE_URL = re.compile(r"https?://\S+")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)

PROSE_EXT = (".md",)
EMOJI_EXT = (".md", ".yml", ".yaml", ".json")
CODE_EXT = (".go", ".ts", ".tsx", ".py")
GLOBS = ["*.md", "*.yml", "*.yaml", "*.json", "*.go", "*.ts", "*.tsx", "*.py"]

# Reading level. Grade 10 is the writing TARGET; this gate sits one grade above it, because prose
# can be dense without being unclear. Set from measuring this repo on 2026-08-04: 28 scoreable
# files, median 10.1, max 12.1, min 8.4. A gate at 13 would have failed nothing and proved only
# that the check ran, which is the failure mode the style guide warns about.
READING_GATE = 11.0
MIN_SENTENCES = 25
# Ratcheting ledger of files that were already over the gate when v3 was adopted. It may only
# SHRINK, and only by rewriting prose. Do not add an entry to silence a new failure and do not
# raise READING_GATE: either one converts a real gate into a decoration. The grade recorded with
# each entry is what it measured on adoption day, so progress is visible without rerunning history.
EXEMPT = {
    "docs/guides/runbooks/SECURITY_INCIDENT.md": (12.1, "pre-existing at v3 adoption"),
    ".claude/skills/write-doc.md": (12.1, "pre-existing at v3 adoption"),
    "docs/guides/MONITORING_SETUP.md": (11.8, "pre-existing at v3 adoption"),
    "docs/guides/LINUX_DISTRIBUTION_SUPPORT.md": (11.8, "pre-existing at v3 adoption"),
    "CHANGELOG.md": (11.7, "pre-existing at v3 adoption, 536 sentences of release history"),
    ".github/BRANCH_MANAGEMENT.md": (11.7, "pre-existing at v3 adoption"),
    "docs/guides/DATABASE_MIGRATIONS.md": (11.2, "pre-existing at v3 adoption"),
}


def git(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.strip()
    except Exception:
        return ""


def resolve_files(argv):
    flags = {a for a in argv if a.startswith("--")}
    explicit = [a for a in argv if not a.startswith("--")]
    if explicit:
        return explicit
    if "--all" in flags or "--measure" in flags:
        out = []
        for g in GLOBS:
            out += [f for f in git(["git", "ls-files", g]).splitlines() if f]
        return out
    base = git(["git", "merge-base", "origin/main", "HEAD"]) or "origin/main"
    changed = git(["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD", "--"] + GLOBS)
    if not changed:
        changed = git(["git", "diff", "--name-only", "--cached", "--"] + GLOBS)
    return [f for f in changed.splitlines() if f]


def strip_targets(line):
    """Remove link targets and bare URLs, keeping visible link text."""
    return BARE_URL.sub("", MD_LINK.sub(r"\1", line))


def line_findings(raw, is_prose, do_emoji, in_fence, is_comment=False):
    """Return (list of (label, token), new_in_fence) for one line. Reports every match, not just
    the first, so a heavily affected line can be cleaned in one pass."""
    if is_prose and FENCE.match(raw):
        return [], (not in_fence)
    if in_fence or ALLOW.search(raw):
        return [], in_fence
    out = []
    if do_emoji:
        m = EMOJI.search(raw)
        if m:
            out.append(("emoji", m.group(0)))
    if is_prose or is_comment:
        line = strip_targets(INLINE_CODE.sub("", raw))
        if is_prose and EM_DASH.search(line):
            out.append(("em-dash", "—"))
        for _term, rx in WORD_RES + PHRASE_RES:
            mm = rx.search(line)
            if mm:
                out.append(("ai-speak", mm.group(0)))
        for rx in CONTRACTION_RES:
            mm = rx.search(line)
            if mm:
                out.append(("ai-speak", mm.group(0)))
        for _b, us, rx in BRITISH_RES:
            mm = rx.search(line)
            if mm:
                out.append(("british", f"{mm.group(0)} -> {us}"))
    return out, in_fence


# Comment extraction. Deliberately simple: a line is treated as a comment when it starts with a
# comment marker, or contains one outside a string. Anything ambiguous is skipped rather than
# guessed at, because a false finding in source is more annoying than a missed one in a comment.
COMMENT_STARTS = {
    ".go": ("//",), ".ts": ("//",), ".tsx": ("//",), ".py": ("#",),
}


def comment_text(path, raw):
    """Return the prose part of a comment line, or None when the line is not a whole-line comment."""
    for marker in COMMENT_STARTS.get(path[path.rfind("."):], ()):
        s = raw.strip()
        if s.startswith(marker):
            return s[len(marker):]
        if s.startswith("*") and path.endswith((".go", ".ts", ".tsx")):
            return s[1:]
    return None


def count_syllables(word):
    """Heuristic syllable count. Good enough for a corpus average; exact counts are not needed."""
    w = re.sub(r"[^a-z]", "", word.lower())
    if not w:
        return 0
    groups = re.findall(r"[aeiouy]+", w)
    n = len(groups)
    if w.endswith("e") and not w.endswith(("le", "ee", "ye")) and n > 1:
        n -= 1
    return max(1, n)


SENT_SPLIT = re.compile(r"(?<=[.!?])\s+")


def prose_of(path):
    """Extract scoreable prose from a Markdown file: no code, tables, headings, links or lists."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return ""
    text = HTML_COMMENT.sub(" ", text)
    out, in_fence = [], False
    for raw in text.split("\n"):
        if FENCE.match(raw):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        s = raw.strip()
        if not s or s.startswith("#") or s.startswith("|") or s.startswith(">"):
            continue          # headings, tables and quotes are not the author's sentences
        if s.startswith(("- ", "* ", "+ ")) or re.match(r"^\d+\.\s", s):
            s = re.sub(r"^([-*+]|\d+\.)\s+", "", s)   # keep list prose, drop the marker
        s = strip_targets(INLINE_CODE.sub(" ", s))
        s = re.sub(r"[*_`#]+", "", s)
        if s.strip():
            out.append(s.strip())
    return " ".join(out)


def grade_level(prose):
    """Flesch-Kincaid grade. Returns (grade, sentences, words) or (None, n, w) when too short."""
    sentences = [s for s in SENT_SPLIT.split(prose) if len(s.split()) >= 3]
    words = re.findall(r"[A-Za-z][A-Za-z'-]*", prose)
    if len(sentences) < MIN_SENTENCES or not words:
        return None, len(sentences), len(words)
    syl = sum(count_syllables(w) for w in words)
    grade = 0.39 * (len(words) / len(sentences)) + 11.8 * (syl / len(words)) - 15.59
    return round(grade, 1), len(sentences), len(words)


def check_file(path, report):
    is_prose = path.endswith(PROSE_EXT)
    do_emoji = path.endswith(EMOJI_EXT)
    is_code = path.endswith(CODE_EXT)
    if not (is_prose or do_emoji or is_code):
        return 0
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return 0
    findings = 0
    in_fence = False
    for n, raw in enumerate(lines, 1):
        if is_code:
            body = comment_text(path, raw)
            if body is None:
                continue
            hits, _ = line_findings(body, False, False, False, is_comment=True)
        else:
            hits, in_fence = line_findings(raw, is_prose, do_emoji, in_fence)
        for label, token in hits:
            report(path, n, label, token)
            findings += 1

    if is_prose:
        g, sents, _ = grade_level(prose_of(path))
        if g is not None and g > READING_GATE and path not in EXEMPT:
            report(path, 0, "reading-level",
                   f"grade {g} over gate {READING_GATE} ({sents} sentences). Target is 10: "
                   "split sentences over ~25 words, one idea each")
            findings += 1
    return findings


def measure(files):
    """Report grade levels without gating. Use this to SET the gate, never to raise it."""
    rows = []
    for path in files:
        if not path.endswith(PROSE_EXT):
            continue
        g, sents, words = grade_level(prose_of(path))
        if g is not None:
            rows.append((g, sents, words, path))
    if not rows:
        print("doc-style: no file has enough prose to score")
        return 0
    rows.sort(reverse=True)
    grades = sorted(g for g, _, _, _ in rows)
    mid = grades[len(grades) // 2]
    print(f"scored {len(rows)} file(s)   median grade {mid}   max {grades[-1]}   min {grades[0]}")
    print(f"current gate {READING_GATE}, target 10\n")
    for g, sents, _w, path in rows[:25]:
        flag = "  OVER" if g > READING_GATE else ""
        print(f"  {g:5.1f}  {sents:4d} sentences  {path}{flag}")
    over = [r for r in rows if r[0] > READING_GATE]
    print(f"\n{len(over)} file(s) over the gate of {READING_GATE}")
    return 0


def selftest():
    """Positive and negative cases. Returns the number of failures."""
    must_flag = [
        "OpenWatch leverages Kensa for remediation.",
        "The team is leveraging the queue.",
        "It utilizes PostgreSQL.",
        "Kensa empowers operators.",
        "A streamlined workflow.",
        "It facilitates rollback.",
        "It is worth mentioning that scans are queued.",
        "You are all set.",
        "Great question.",
        "harness the power of X.",
        "unlock the potential of the fleet.",
        "A seamless, robust, powerful platform.",
        "The rollback behaviour is documented.",
        "We summarise the findings.",
        "Whilst the scan runs, the host stays up.",
        "The licence file is at the repo root.",
    ]
    must_pass = [
        "The test harness runs nightly.",
        "Unlock the account.",
        "Run with elevated privileges.",
        "Set unlock_time in the config.",
        "It reads the value and returns it.",
        "The behavior is documented.",
        "We summarize the findings.",
        "While the scan runs, the host stays up.",
        "See https://example.com/en-gb/behaviour for the upstream note.",
        "The license file is at the repo root.",
    ]
    fails = 0
    for text in must_flag:
        hits, _ = line_findings(text, True, True, False)
        if not hits:
            sys.stderr.write(f"  selftest: expected a finding, got none: {text!r}\n")
            fails += 1
    for text in must_pass:
        hits, _ = line_findings(text, True, True, False)
        if hits:
            sys.stderr.write(f"  selftest: expected clean, got {hits}: {text!r}\n")
            fails += 1
    hits, _ = line_findings('  title: "Bug report \U0001F41B"', is_prose=False, do_emoji=True, in_fence=False)
    if not any(l == "emoji" for l, _ in hits):
        sys.stderr.write("  selftest: emoji not caught in a structured (.yml) line\n")
        fails += 1
    # A comment carries the writing rules; the code around it does not.
    hits, _ = line_findings("// This leverages the pool to summarise results.", False, False, False, is_comment=True)
    if len([h for h in hits if h[0] in ("ai-speak", "british")]) < 2:
        sys.stderr.write("  selftest: comment rules did not fire on a code comment\n")
        fails += 1
    # Reading level: the guide's own worked example, both halves.
    plain = ("Kensa captures the file before it changes anything. " * 30)
    dense = ("Prior to the application of any modification, Kensa performs a capture operation "
             "against the target file, which, in the event that subsequent validation is "
             "unsuccessful, is subsequently utilized to effect a restoration. " * 30)
    gp, _, _ = grade_level(plain)
    gd, _, _ = grade_level(dense)
    if gp is None or gd is None or not gp < gd:
        sys.stderr.write(f"  selftest: reading level did not separate plain from dense ({gp} vs {gd})\n")
        fails += 1
    if fails:
        sys.stderr.write(f"\ndoc-style selftest FAILED: {fails} case(s).\n")
    else:
        print("doc-style selftest: all cases pass")
    return fails


def main():
    argv = sys.argv[1:]
    if "--version" in argv:
        h = hashlib.sha256(open(__file__, "rb").read()).hexdigest()
        print(f"doc-style check version {VERSION}  sha256 {h}")
        return 0
    if "--selftest" in argv:
        return 1 if selftest() else 0

    files = resolve_files(argv)
    if "--measure" in argv:
        return measure(files)

    checkable = [f for f in files if f.endswith(EMOJI_EXT + CODE_EXT)]
    if not checkable:
        print("doc-style: nothing to check")
        return 0

    findings = 0

    def report(path, n, label, token):
        where = f"{path}:{n}" if n else path
        sys.stderr.write(f"  {where}  {label}: {token}\n")

    for path in checkable:
        findings += check_file(path, report)

    if findings:
        sys.stderr.write(
            f"\ndoc-style FAILED: {findings} finding(s). "
            "See dev/DEVELOPER_DOCUMENTATION_STYLE_GUIDE.\n"
            "Fix the prose. Add `doc-style: allow` to a line a maintainer has cleared. "
            "Do NOT raise READING_GATE or add to EXEMPT to silence a new failure.\n"
        )
        return 1
    print(f"doc-style: {len(checkable)} file(s) clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
