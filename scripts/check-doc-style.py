#!/usr/bin/env python3
"""Hanalyx documentation style check (language-neutral: runs anywhere python3 is present).

Enforces the prohibited list from the developer documentation style guide (canonical copy:
Context Plane dev/DEVELOPER_DOCUMENTATION_STYLE_GUIDE):

  1. Em dashes (the U+2014 character).            markdown prose             per line
  2. AI-speak filler and hype words and phrases.  markdown prose + comments  per line
  3. Emojis / decorative pictographs.             markdown AND .yml/.yaml/.json
  4. British spellings (US English rule).         markdown prose + comments  per line
  5. Reading level above the gate.                markdown prose             per FILE

Document class (v5). The guide scopes itself: founding and strategy documents (mission, vision,
roadmap) and marketing copy are "out of scope (formatting)" while remaining "bound by the trust
and clarity principles". So rules 1 and 3, which are punctuation and decoration, do not apply to
those documents. Rules 2, 4 and 5 do, because voice and clarity are exactly what the guide keeps
in scope. See formatting_exempt().

v4 reconciles three independently written v3 implementations (kensa, openwatch, website), which
shared a version number and nothing else. What each contributed, and why v4 is not just one of
them: openwatch scanned CODE COMMENTS, which the guide requires and the other two lacked. kensa
documented the ratcheting exemption ledger and set its gate by measuring its own corpus. This
implementation had the only spelling table free of false positives. All three flagged at least
one correct US spelling, which is worse than missing a British one, because it teaches writers
to ignore the check.

The finding label is "us-english". kensa called it "us-spelling" and openwatch called it
"british"; anything grepping for those needs updating.

Scope (HP-008). Em dashes, AI-speak and US English are prose rules and run on Markdown only. The
emoji rule is not a prose rule, so it also runs on structured files (.yml, .yaml, .json), where
emoji in issue templates and workflows are otherwise invisible to the gate.

Matching (HP-003).
- Single always-hype words match their inflected forms (leverage / leverages / leveraging /
  streamlined), so the common half of AI speak no longer escapes the check.
- Words that also have a legitimate technical sense (harness, unlock, elevate, delve, embark)
  are matched only inside their hype phrase, never as a bare word, so "test harness",
  "unlock_time", and "elevated privileges" are not flagged.
- Fenced code blocks and inline `code` spans in Markdown are exempt (code is not prose).
- A line with `<!-- doc-style: allow -->` is skipped when a maintainer has cleared the term.

US English (v3). An explicit British-to-US table, never a blanket "-ise to -ize" rule: advise,
surprise, exercise and comprise are correct US spellings and a suffix rule would flag all of
them. Inline code, fenced blocks, URLs and Markdown link targets are stripped before matching,
so an identifier, a third-party URL, or a proper noun inside a link never trips the check. Keep
a British spelling inside a quotation, a proper noun, or a standard's own title with the
per-line allow escape.

Reading level (v3). Flesch-Kincaid grade, computed per file over prose only. Headings, tables,
fenced and inline code, link targets, HTML comments and front matter are removed first, so terms
of art and command names never raise the grade: the target constrains sentence construction, not
vocabulary. Files with fewer than MIN_SENTENCES scored sentences are skipped, because the metric
is unstable on short files. The writing target is grade 10. The GATE sits above the target,
because prose can be dense without being unclear, and it is set from a measurement of this
repo's own corpus (see --grades).

Usage:
  python3 scripts/check-doc-style.py <file> [more ...]   # check specific files
  python3 scripts/check-doc-style.py --changed           # files changed vs origin/main
  python3 scripts/check-doc-style.py --all               # all tracked files
  python3 scripts/check-doc-style.py --grades            # print each file's grade, no gate
  python3 scripts/check-doc-style.py --version           # print version and self sha256
  python3 scripts/check-doc-style.py --selftest          # run built-in matching tests
"""
import hashlib
import re
import subprocess
import sys

VERSION = "5"

# --- Reading level ----------------------------------------------------------------------------
# The writing TARGET from the style guide. Not the gate: it is what an author aims at.
READING_TARGET = 10.0
# The failing gate, set by measuring this repo's corpus (--grades) rather than picked to be safe.
# A gate no file exceeds proves only that the check ran.
# Set by measuring this repo on 2026-08-06 with --grades, per the adoption notes:
# 29 files, median 9.2, p75 10.2, p90 11.4, max 14.7. The gate sits one grade clear of p90 and
# two above the target, which catches the genuine outlier without manufacturing churn. The
# previous local v3 used 11.0, calibrated on a BROKEN measurement: its extractor terminated every
# unpunctuated line, so an 80-column wrapped sentence counted as three and the whole corpus read
# about two grades low. Do not carry that number forward.
READING_GATE = 12.0
# Below this many scored sentences, Flesch-Kincaid is noise. The guide sets the floor at 25.
MIN_SENTENCES = 25

# Per-file reading-level exemptions. This is a RATCHETING LEDGER: entries may be removed by
# rewriting the prose, never added to raise the gate, and never given a value above the grade the
# file scored when it was added. Each needs a reason.
READING_EXEMPT = {
    # path: (max_grade, reason)
    "docs/CAPABILITY_STATEMENT.md": (
        13.7,
        "Federal buyer-facing document. The style guide gives capability statements formal "
        "conventions (title-case headings, no contractions) and says not to correct them to "
        "dev-doc formatting, which raises the grade on its own. Measured 13.7 on 2026-08-05.",
    ),
}

# --- Document class ---------------------------------------------------------------------------
# The style guide scopes itself: "Out of scope (formatting): Founding and strategy documents
# (mission, vision, roadmap) and marketing copy, which have their own voice. They remain bound by
# the trust and clarity principles in this guide."
#
# So the FORMATTING rules do not bind those documents, while the trust and clarity rules still do:
#
#   exempt   em dashes, emojis          punctuation and decoration, nothing else
#   binding  AI speak, US English       trust and voice, which the guide keeps in scope
#   binding  reading level              a clarity principle, which the guide keeps in scope
#
# Without this, editing one word in a vision document pulled its punctuation into a gate the guide
# does not apply to it. Detection is by filename token, not substring, so REVISION_HISTORY.md is
# not mistaken for a vision document.
FORMATTING_EXEMPT_TOKENS = {"MISSION", "VISION", "ROADMAP", "STRATEGY"}
FORMATTING_EXEMPT_MARK = re.compile(r"<!--\s*doc-style:\s*formatting-exempt\s*-->")


def formatting_exempt(path, text=""):
    """True when the guide's formatting rules do not bind this document."""
    stem = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    if set(re.split(r"[^A-Za-z0-9]+", stem.upper())) & FORMATTING_EXEMPT_TOKENS:
        return True
    if "/roadmap/" in "/" + path:
        return True
    # A document may also declare itself, for anything the filename does not reveal.
    return bool(FORMATTING_EXEMPT_MARK.search(text))


# --- AI speak ---------------------------------------------------------------------------------
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

# --- US English -------------------------------------------------------------------------------
# British stem -> US stem, matched with the inflections listed beside it, so the table stays
# short without missing plurals or -isation forms. Deliberately an explicit table and never a
# generic rule: a blanket "-ise to -ize" would flag advise, surprise, exercise, comprise,
# revise and supervise, all correct US English. doc-style: allow
BRIT_US = [
    # -our
    ("behaviour", "behavior", ("s", "al", "ally")),
    ("colour", "color", ("s", "ed", "ing", "ful")),
    ("favour", "favor", ("s", "ed", "ing", "able", "ably", "ite", "ites")),
    ("honour", "honor", ("s", "ed", "ing", "able")),
    ("labour", "labor", ("s", "ed", "ing")),
    ("neighbour", "neighbor", ("s", "ing", "hood")),
    ("rumour", "rumor", ("s", "ed")),
    ("flavour", "flavor", ("s", "ed", "ing")),
    ("endeavour", "endeavor", ("s", "ed", "ing")),
    # -ise / -isation. The stem is truncated before the "e", so one entry covers every
    # inflected form in the family. A table that kept the "e" misses each -ing and -ation
    # form, which is how thirteen British spellings escaped the first version of this
    # check. doc-style: allow
    ("organis", "organiz", ("e", "es", "ed", "ing", "ation", "ations", "ational", "er", "ers")),
    ("recognis", "recogniz", ("e", "es", "ed", "ing", "able")),
    ("summaris", "summariz", ("e", "es", "ed", "ing", "ation")),
    ("generalis", "generaliz", ("e", "es", "ed", "ing", "ation", "able")),
    ("initialis", "initializ", ("e", "es", "ed", "ing", "ation", "er", "ers")),
    ("serialis", "serializ", ("e", "es", "ed", "ing", "ation", "er")),
    ("normalis", "normaliz", ("e", "es", "ed", "ing", "ation")),
    ("optimis", "optimiz", ("e", "es", "ed", "ing", "ation", "er")),
    ("prioritis", "prioritiz", ("e", "es", "ed", "ing", "ation")),
    ("standardis", "standardiz", ("e", "es", "ed", "ing", "ation")),
    ("customis", "customiz", ("e", "es", "ed", "ing", "ation")),
    ("minimis", "minimiz", ("e", "es", "ed", "ing", "ation")),
    ("maximis", "maximiz", ("e", "es", "ed", "ing", "ation")),
    ("authoris", "authoriz", ("e", "es", "ed", "ing", "ation", "ations")),
    ("emphasis", "emphasiz", ("e", "ed", "ing")),
    ("specialis", "specializ", ("e", "es", "ed", "ing", "ation")),
    ("synchronis", "synchroniz", ("e", "es", "ed", "ing", "ation")),
    ("categoris", "categoriz", ("e", "es", "ed", "ing", "ation")),
    ("realis", "realiz", ("e", "es", "ed", "ing", "ation")),
    ("apologis", "apologiz", ("e", "es", "ed", "ing")),
    ("criticis", "criticiz", ("e", "es", "ed", "ing")),
    ("sanitis", "sanitiz", ("e", "es", "ed", "ing", "ation", "er")),
    ("virtualis", "virtualiz", ("e", "es", "ed", "ing", "ation")),
    # -yse. Truncated stem, and deliberately no "es" or "is" suffix: "analyses" and "analysis"
    # are both correct US English, so matching them would flag correct spelling. Losing the
    # British third-person form is the right trade. kensa and openwatch both flag "analyses".
    ("analys", "analyz", ("e", "ed", "ing", "er", "ers")),
    ("paralys", "paralyz", ("e", "ed", "ing")),
    # -re
    # Split out: "center" + "d" is not a word, and the suggestion is built by
    # concatenation. Every entry must satisfy us_stem + matched_suffix == real word.
    ("centre", "center", ("s",)),
    ("centred", "centered", ()),
    ("centring", "centering", ()),
    ("metre", "meter", ("s",)),
    ("fibre", "fiber", ("s",)),
    ("litre", "liter", ("s",)),
    ("theatre", "theater", ("s",)),
    # -ce nouns
    ("licence", "license", ("s",)),
    ("defence", "defense", ("s",)),
    ("offence", "offense", ("s",)),
    ("pretence", "pretense", ("s",)),
    ("practise", "practice", ("s", "d")),
    # doubled consonants
    ("modelled", "modeled", ()),
    ("modelling", "modeling", ()),
    ("cancelled", "canceled", ()),
    ("cancelling", "canceling", ()),
    ("labelled", "labeled", ()),
    ("labelling", "labeling", ()),
    ("signalled", "signaled", ()),
    ("signalling", "signaling", ()),
    ("travelled", "traveled", ()),
    ("travelling", "traveling", ()),
    ("fuelled", "fueled", ()),
    ("marvellous", "marvelous", ()),
    # misc. Deliberately NOT listed, because each is also correct US English and flagging it
    # would make the check wrong: burnt (as in burnt-orange), spelt (the grain), dialogue,
    # acknowledgement, towards. Never flag a correct US spelling. doc-style: allow
    ("judgement", "judgment", ("s",)),
    ("catalogue", "catalog", ("s", "d")),
    ("programme", "program", ("s",)),
    ("whilst", "while", ()),
    ("sceptical", "skeptical", ()),
    ("sceptic", "skeptic", ("s",)),
    ("amongst", "among", ()),
    ("artefact", "artifact", ("s",)),
    ("grey", "gray", ("s", "ed")),
    ("enquiry", "inquiry", ()),
    ("fulfil", "fulfill", ("s",)),
    ("enrol", "enroll", ("s",)),
    ("instal", "install", ("s",)),
    ("storey", "story", ("s",)),
    ("learnt", "learned", ()),
]


def brit_re(stem, suffixes):
    """One regex per British stem, covering the listed inflections. Word-boundary anchored so an
    identifier such as `colour_map` is not matched on the bare stem alone."""
    alts = "|".join(re.escape(s) for s in suffixes if s)
    tail = f"(?:{alts})?" if alts else ""
    return re.compile(rf"\b{re.escape(stem)}{tail}\b", re.I)


BRIT_RES = [(b, us, brit_re(b, sfx)) for b, us, sfx in BRIT_US]


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
ALLOW = re.compile(r"<!--\s*doc-style:\s*allow\s*-->")
URL = re.compile(r"https?://\S+|\bwww\.\S+")
LINK_TARGET = re.compile(r"\]\([^)]*\)")
AUTOLINK = re.compile(r"<[^ >]+>")

PROSE_EXT = (".md",)
EMOJI_EXT = (".md", ".yml", ".yaml", ".json")
# US English and AI speak are WRITING rules, not document rules. The guide binds them to "code
# comments, commit messages, and pull request text", so they also run on comments in source.
# Adopted from openwatch's v3, which had this and this repo's v3 did not.
# .mjs and .cjs are the same JavaScript, only a different module system. Omitting them left the
# comments in every ES-module script invisible to the check, including this repo's own sync
# scripts. The same reasoning covers .mts and .cts on the TypeScript side.
# .sql carries prose too. A migration's header comment is where the reason for a schema change is
# written, and those comments were invisible here until 2026-08-13: .sql was in neither tuple, so
# every check returned without reading the file. Four US English defects had accumulated behind
# that gap.
CODE_EXT = (".go", ".ts", ".tsx", ".mts", ".cts", ".py", ".js", ".jsx", ".mjs", ".cjs", ".sql")
GLOBS = ["*.md", "*.yml", "*.yaml", "*.json", "*.go", "*.ts", "*.tsx", "*.mts", "*.cts",
         "*.py", "*.js", "*.jsx", "*.mjs", "*.cjs", "*.sql"]

# Comment extraction, deliberately conservative: only a WHOLE-LINE comment is scanned. A trailing
# comment after code, or a marker inside a string literal, is skipped rather than guessed at. A
# false finding in source costs more attention than a missed one in a comment.
COMMENT_STARTS = {
    ".go": ("//",), ".ts": ("//",), ".tsx": ("//",), ".mts": ("//",), ".cts": ("//",),
    ".js": ("//",), ".jsx": ("//",), ".mjs": ("//",), ".cjs": ("//",),
    ".py": ("#",),
    ".sql": ("--",),
}
# The C-family languages, for the block-comment continuation line ( * inside a doc comment).
C_FAMILY = (".go", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
CODE_ALLOW = re.compile(r"doc-style:\s*allow")


def comment_text(path, raw):
    """Return the prose inside a whole-line comment, or None when the line is not one."""
    ext = path[path.rfind("."):]
    stripped = raw.lstrip()
    for marker in COMMENT_STARTS.get(ext, ()):
        if stripped.startswith(marker):
            return stripped[len(marker):].strip()
    # Block-comment bodies in C-family files: a line whose first token is * inside /* ... */.
    if ext in C_FAMILY and stripped.startswith("*") \
            and not stripped.startswith("*/"):
        return stripped[1:].strip()
    return None


def strip_noncode_targets(line):
    """Remove the parts of a Markdown line that are not prose a reader reads as English."""
    line = INLINE_CODE.sub(" ", line)
    line = LINK_TARGET.sub("] ", line)
    line = URL.sub(" ", line)
    line = AUTOLINK.sub(" ", line)
    return line


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
    if "--all" in flags or "--grades" in flags:
        out = []
        for g in GLOBS:
            out += [f for f in git(["git", "ls-files", g]).splitlines() if f]
        return out
    base = git(["git", "merge-base", "origin/main", "HEAD"]) or "origin/main"
    changed = git(["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD", "--"] + GLOBS)
    if not changed:
        changed = git(["git", "diff", "--name-only", "--cached", "--"] + GLOBS)
    return [f for f in changed.splitlines() if f]


def line_findings(raw, is_prose, do_emoji, in_fence, is_comment=False, skip_formatting=False):
    """Return (list of (label, token), new_in_fence) for one line. Reports every match, not just
    the first, so a heavily affected line can be cleaned in one pass."""
    if is_prose and FENCE.match(raw):
        return [], (not in_fence)
    if in_fence or ALLOW.search(raw):
        return [], in_fence
    out = []
    if do_emoji and not skip_formatting:
        m = EMOJI.search(raw)
        if m:
            out.append(("emoji", m.group(0)))
    if is_prose:
        line = INLINE_CODE.sub("", raw)
        # Em dashes are a DOCUMENT rule, not a writing rule: the style guide prohibits them in
        # developer docs, and a code comment is not a doc. US English and AI speak do bind
        # comments. Matches openwatch's v3 scope.
        #
        # Two checks are skipped in a comment, not one. This is the em dash; the emoji check is
        # the other, and check_file skips it by passing do_emoji=False for every CODE_EXT file.
        #
        # Settled by founder direction 2026-08-13: an em dash is a document rule, so it binds
        # documentation and not code comments. This line is correct and stays. The repo guidance
        # that claimed otherwise was the defect and has been corrected. See CP bugs/OW-015.
        if not is_comment and not skip_formatting and EM_DASH.search(line):
            out.append(("em-dash", "—"))
        for _term, rx in WORD_RES + PHRASE_RES:
            mm = rx.search(line)
            if mm:
                out.append(("ai-speak", mm.group(0)))
        for rx in CONTRACTION_RES:
            mm = rx.search(line)
            if mm:
                out.append(("ai-speak", mm.group(0)))
        spell = strip_noncode_targets(raw)
        for brit, us, rx in BRIT_RES:
            mm = rx.search(spell)
            if mm:
                # Build the suggestion by carrying the matched suffix onto the US stem, so a
                # truncated stem never leaks into the advice. Every table entry is chosen so
                # that the US stem plus the matched suffix spells a real word. doc-style: allow
                matched = mm.group(0)
                out.append(("us-english", f"{matched} (use US {us + matched[len(brit):].lower()})"))
    return out, in_fence


# --- Reading level ----------------------------------------------------------------------------
VOWELS = "aeiouy"
WORD_TOKEN = re.compile(r"[A-Za-z][A-Za-z'’-]*")
SENT_END = re.compile(r"[.!?]+(?=\s|$)")
TABLE_ROW = re.compile(r"^\s*\|")
HEADING = re.compile(r"^\s*#{1,6}\s")
LIST_MARKER = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+")
BLOCKQUOTE = re.compile(r"^\s*>\s?")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
BOLD_ITALIC = re.compile(r"[*_]{1,3}")
FRONTMATTER = re.compile(r"\A---\n.*?\n---\n", re.S)


def syllables(word):
    """Vowel-group count with a silent trailing e, floored at 1. The standard heuristic; it is
    approximate by design, and Flesch-Kincaid is only meaningful in aggregate anyway."""
    w = word.lower().strip("'’-")
    if not w:
        return 0
    count, prev_vowel = 0, False
    for ch in w:
        is_vowel = ch in VOWELS
        if is_vowel and not prev_vowel:
            count += 1
        prev_vowel = is_vowel
    if w.endswith("e") and not w.endswith(("le", "ee", "ye")) and count > 1:
        count -= 1
    return max(count, 1)


def prose_of(text):
    """Reduce a Markdown document to the prose a human reads as sentences."""
    text = FRONTMATTER.sub("", text)
    text = HTML_COMMENT.sub(" ", text)
    kept, in_fence = [], False
    for raw in text.split("\n"):
        if FENCE.match(raw):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if HEADING.match(raw) or TABLE_ROW.match(raw):
            continue
        line = BLOCKQUOTE.sub("", raw)
        line = LIST_MARKER.sub("", line)
        line = strip_noncode_targets(line)
        line = BOLD_ITALIC.sub("", line)
        kept.append(line)
    return "\n".join(kept)


def grade_of(text):
    """Flesch-Kincaid grade over the prose of a Markdown document.

    Returns (grade, sentences, words) or (None, sentences, words) when there is too little prose
    to score. Paragraphs are the unit: a paragraph with no terminal punctuation, such as a bullet
    fragment, counts as one sentence rather than being merged into its neighbour."""
    prose = prose_of(text)
    sentences = words = sylls = 0
    for para in re.split(r"\n\s*\n", prose):
        para = para.strip()
        if not para:
            continue
        toks = WORD_TOKEN.findall(para)
        if not toks:
            continue
        words += len(toks)
        sylls += sum(syllables(t) for t in toks)
        sentences += max(len(SENT_END.findall(para)), 1)
    if sentences < MIN_SENTENCES or words == 0:
        return None, sentences, words
    grade = 0.39 * (words / sentences) + 11.8 * (sylls / words) - 15.59
    return round(grade, 1), sentences, words


def check_file(path, report):
    is_prose = path.endswith(PROSE_EXT)
    do_emoji = path.endswith(EMOJI_EXT)
    is_code = path.endswith(CODE_EXT)
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return 0
    # Founding and strategy documents keep their own voice on punctuation and decoration.
    skip_fmt = is_prose and formatting_exempt(path, text)
    findings = 0
    in_fence = False
    for n, raw in enumerate(text.split("\n"), 1):
        if is_code:
            body = comment_text(path, raw)
            if body is None or CODE_ALLOW.search(raw):
                continue
            # Comments get the prose rules only. No emoji rule (source may legitimately carry
            # one in a test fixture) and no fence tracking (a comment is never a fenced block).
            hits, _ = line_findings(body, True, False, False, is_comment=True)
        else:
            hits, in_fence = line_findings(raw, is_prose, do_emoji, in_fence,
                                           skip_formatting=skip_fmt)
        for label, token in hits:
            report(path, n, label, token)
            findings += 1
    if is_prose:
        grade, sents, _ = grade_of(text)
        if grade is not None:
            limit = READING_EXEMPT.get(path, (READING_GATE, ""))[0]
            if grade > limit:
                report(path, 0, "reading-level",
                       f"grade {grade} over {limit} across {sents} sentences (target {READING_TARGET})")
                findings += 1
    return findings


def selftest():
    """Positive and negative cases. Returns the number of failures."""
    must_flag = [
        "OpenWatch leverages Kensa for remediation.",
        "The team is leveraging the queue.",
        "It utilizes PostgreSQL.",
        "Kensa empowers operators.",
        "A streamlined workflow.",
        "This streamlines onboarding.",
        "It facilitates rollback.",
        "It is worth mentioning that scans are queued.",
        "You are all set.",
        "We have got you covered.",
        "Great question.",
        "Certainly! Here is the command.",
        "harness the power of X.",
        "unlock the potential of the fleet.",
        "A seamless, robust, powerful platform.",
        # US English
        "The behaviour of the scheduler changed.",
        "Document the observed behaviours.",
        "We organise the rules by category.",
        "The organisation owns the key.",
        "Analyse the transaction log.",
        "Set the licence key.",
        "The control centre is offline.",
        "The change was cancelled.",
        "Use your judgement.",
        "Whilst the scan runs, hosts stay locked.",
        "Colour tokens come from the theme.",
        "The catalogue lists 751 rules.",
    ]
    must_pass = [
        "The test harness runs nightly.",
        "Unlock the account.",
        "Run with elevated privileges.",
        "Set unlock_time in the config.",
        "We foster adoption across teams.",
        "The scheduler embarked and returned.",
        "It reads the value and returns it.",
        # US spellings, and -ise words that are correct in US English
        "The behavior of the scheduler changed.",
        "We organize the rules by category.",
        "Analyze the transaction log.",
        "We advise a dry run first.",
        "The result may surprise you.",
        "Exercise the rollback path before shipping.",
        "The suite comprises 895 tests.",
        "Revise the spec, then the code.",
        "A senior engineer supervises the release.",
        "Otherwise, the host stays unchanged.",
        "The analyses agree with the measurement.",
        "The burnt-orange theme was replaced.",
        "Spelt flour is not a spelling error.",
        "The dialogue between the agents is logged.",
        "Send an acknowledgement to the caller.",
        "The scan works towards a full pass.",
        "Two paralyses were recorded in the study.",
        "The crisis analyses are complete.",
        "Enterprise licensing is handled by legal.",
        "The `colour_map` identifier stays as it is.",
        "See [the guide](https://example.com/en-GB/behaviour) for details.",
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
    # Extension coverage. A module system is not a language: .mjs and .cjs are JavaScript and
    # their comments must be read like any other. Asserted per extension so dropping one from
    # CODE_EXT fails here rather than silently going unchecked.
    for ext, line, want in (
        (".mjs", "// we organise the corpus", "organise"),
        (".cjs", "// we organise the corpus", "organise"),
        (".mts", "// we organise the corpus", "organise"),
        (".js",  "// we organise the corpus", "organise"),
        (".py",  "#  we organise the corpus", "organise"),
        (".go",  " * we organise the corpus", "organise"),
        (".sql", "-- we organise the corpus", "organise"),
    ):
        body = comment_text("a" + ext, line)
        if body is None or want not in body:
            sys.stderr.write(f"  selftest: comment not extracted from {ext}: {body!r}\n")
            fails += 1
    if comment_text("a.mjs", "const x = 1; // trailing") is not None:
        sys.stderr.write("  selftest: a trailing comment was treated as a whole-line comment\n")
        fails += 1

    # Document class. Founding and strategy documents are exempt from FORMATTING only, so em
    # dashes and emojis pass while AI speak, US English and reading level still bind. Detection
    # is by filename token so a name that merely contains the letters does not match.
    for p_exempt in ("docs/SPECTER_VISION.md", "docs/HANALYX_MISSION_AND_ROADMAP.md",
                     "docs/roadmap/PHASE-4-versioned-docs-rules-sync.md",
                     "docs/HANALYX_18_MONTH_STRATEGY.md"):
        if not formatting_exempt(p_exempt):
            sys.stderr.write(f"  selftest: {p_exempt} should be formatting-exempt\n")
            fails += 1
    for p_bound in ("docs/REVISION_HISTORY.md", "README.md", "docs/THEME_SYSTEM.md",
                    "content/docs/kensa/quickstart.md"):
        if formatting_exempt(p_bound):
            sys.stderr.write(f"  selftest: {p_bound} should NOT be formatting-exempt\n")
            fails += 1
    if not formatting_exempt("docs/anything.md", "<!-- doc-style: formatting-exempt -->\n"):
        sys.stderr.write("  selftest: the self-declaring marker was ignored\n")
        fails += 1
    # In an exempt document, punctuation and decoration pass...
    hits, _ = line_findings("a state \u2014 see the note", True, True, False, skip_formatting=True)
    if any(l in ("em-dash", "emoji") for l, _ in hits):
        sys.stderr.write(f"  selftest: formatting flagged in an exempt document: {hits}\n")
        fails += 1
    # ...but trust and clarity rules still bind it.
    hits, _ = line_findings("we organise a seamless rollout", True, True, False, skip_formatting=True)
    if not any(l == "us-english" for l, _ in hits):
        sys.stderr.write("  selftest: US English not applied in an exempt document\n")
        fails += 1
    if not any(l == "ai-speak" for l, _ in hits):
        sys.stderr.write("  selftest: AI speak not applied in an exempt document\n")
        fails += 1

    # Em dashes are a document rule. A comment carrying one is not a finding, but the same
    # comment must still be checked for US English and AI speak.
    hits, _ = line_findings("state \u2014 see the note", True, False, False, is_comment=True)
    if any(l == "em-dash" for l, _ in hits):
        sys.stderr.write("  selftest: em dash flagged inside a code comment\n")
        fails += 1
    hits, _ = line_findings("normalised behaviour", True, False, False, is_comment=True)
    if not any(l == "us-english" for l, _ in hits):
        sys.stderr.write("  selftest: US English not applied to a code comment\n")
        fails += 1
    hits, _ = line_findings("state \u2014 see the note", True, False, False)
    if not any(l == "em-dash" for l, _ in hits):
        sys.stderr.write("  selftest: em dash NOT flagged in markdown prose\n")
        fails += 1

    # Emoji is caught in a structured file even though the prose rules are not applied.
    hits, _ = line_findings('  title: "Bug report \U0001F41B"', is_prose=False, do_emoji=True, in_fence=False)
    if not any(l == "emoji" for l, _ in hits):
        sys.stderr.write("  selftest: emoji not caught in a structured (.yml) line\n")
        fails += 1

    # Reading level: the guide's own worked example. Plain prose scores near grade 10 or below;
    # the padded rewrite of the same content scores far above it. Both are repeated past
    # MIN_SENTENCES so the scorer runs.
    plain = ("Kensa captures the file before it changes anything. If validation fails, it "
             "restores that capture and records the rollback.\n\n") * 14
    dense = ("Prior to the application of any modification, Kensa performs a capture operation "
             "against the target file, which, in the event that subsequent validation is "
             "unsuccessful, is subsequently utilized to effect a restoration of the previously "
             "extant configuration state.\n\n") * 26
    g_plain, _, _ = grade_of(plain)
    g_dense, _, _ = grade_of(dense)
    if g_plain is None or g_plain > READING_TARGET:
        sys.stderr.write(f"  selftest: plain prose scored {g_plain}, expected <= {READING_TARGET}\n")
        fails += 1
    if g_dense is None or g_dense <= READING_GATE:
        sys.stderr.write(f"  selftest: dense prose scored {g_dense}, expected > {READING_GATE}\n")
        fails += 1
    # Short files are not scored, because the metric is unstable on them.
    g_short, _, _ = grade_of("One short line of prose.\n")
    if g_short is not None:
        sys.stderr.write(f"  selftest: short file scored {g_short}, expected no score\n")
        fails += 1
    # Code and headings must not reach the scorer: a fenced block of long identifiers alone
    # leaves nothing to score.
    g_code, _, _ = grade_of("# Heading\n\n```\nAUDIT_NETLINK_SOCKET_CONFIGURATION_PARAMETER\n```\n")
    if g_code is not None:
        sys.stderr.write(f"  selftest: code-only file scored {g_code}, expected no score\n")
        fails += 1

    if fails:
        sys.stderr.write(f"\ndoc-style selftest FAILED: {fails} case(s).\n")
    else:
        print("doc-style selftest: all cases pass")
    return fails


def print_grades(files):
    """Measure the corpus. Use this to SET the gate, not to confirm a gate you already picked."""
    rows = []
    for path in files:
        if not path.endswith(PROSE_EXT):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                grade, sents, words = grade_of(fh.read())
        except OSError:
            continue
        if grade is not None:
            rows.append((grade, sents, words, path))
    if not rows:
        print("doc-style: no file has enough prose to score")
        return 0
    rows.sort(reverse=True)
    for grade, sents, words, path in rows:
        flag = "  OVER" if grade > READING_EXEMPT.get(path, (READING_GATE, ""))[0] else ""
        print(f"  {grade:5.1f}  {sents:5d} sent  {words:6d} words  {path}{flag}")
    grades = sorted(g for g, _, _, _ in rows)
    mid = grades[len(grades) // 2]
    # Count what the gate would actually fail, exemptions applied, so this line agrees with the
    # check itself. A summary that disagrees with the gate is the kind of number people quote.
    over = sum(1 for g, _, _, p in rows if g > READING_EXEMPT.get(p, (READING_GATE, ""))[0])
    print(f"\n  scored {len(grades)} file(s); median {mid}; "
          f"min {grades[0]}; max {grades[-1]}; {over} over the gate of {READING_GATE} "
          f"(target {READING_TARGET})")
    return 0


def main():
    argv = sys.argv[1:]
    if "--version" in argv:
        h = hashlib.sha256(open(__file__, "rb").read()).hexdigest()
        print(f"doc-style check version {VERSION}  sha256 {h}")
        return 0
    if "--selftest" in argv:
        return 1 if selftest() else 0

    files = resolve_files(argv)
    if "--grades" in argv:
        return print_grades(files)

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
            "Fix the prose, or add `<!-- doc-style: allow -->` to a line a maintainer has cleared.\n"
        )
        return 1
    print(f"doc-style: {len(checkable)} file(s) clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
