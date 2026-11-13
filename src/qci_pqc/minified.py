# Copyright (c) 2026 Quantum Core Institute Inc. MIT License.
"""Minified JavaScript, made readable enough for the line scanner.

A bundler leaves the crypto calls in place and takes away what the patterns key on: the module is
`e`, `createCipheriv` is `t`, the algorithm string is hoisted into `r="aes-128-cbc"`, and the whole
file is one line. Nothing is hidden; it is only renamed.

`expand()` undoes exactly that much and no more:

1. Split the file into statements, so each call is on a line of its own.
2. Put back three kinds of top-level name: an alias of the crypto module, an alias of one of its
   functions (from a destructuring `require` or a named import), and a string constant.
3. Leave a name alone wherever a function or block has a name of its own with the same letter.
   Minifiers reuse `t` in every scope; a name that is a parameter, a local or assigned anywhere in a
   block is never replaced inside it. A missed substitution loses a finding; a wrong one would
   report an algorithm the code does not use.

This is not a JavaScript parser. Regular-expression literals are not recognized, and a file it cannot
split cleanly is returned as it was.
"""
from __future__ import annotations

import re

JS_SUFFIXES = {".js", ".mjs", ".cjs"}
_CRYPTO_MODULE = r"""["'](?:node:)?crypto["']"""
_TOKEN_RE = re.compile(r"""("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)|([A-Za-z_$][\w$]*)|(\s+)|(.)""", re.S)
_STRING_LITERAL_RE = re.compile(r"""^(?:"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')$""")


def is_minified(name: str, text: str) -> bool:
    """A `.min.js` name, or code packed onto very long lines."""
    if name.endswith((".min.js", ".min.mjs", ".min.cjs")):
        return True
    lines = text.splitlines() or [""]
    longest = max(len(x) for x in lines)
    return longest > 500 and text.count(";") + text.count(",") > 20 * len(lines)


def _statements(text: str) -> list[tuple[str, int, int]]:
    """(statement, source line, block depth it starts at). Splits at `;` and at the braces of a
    block, outside strings and parentheses. The braces of an object literal, a destructuring pattern
    or an import list are part of an expression and stay inside their statement."""
    out, cur, start_line, line, depth, paren = [], [], 1, 1, 0, 0
    start_depth, prev = 0, ""
    braces: list[bool] = []            # one entry per open brace: True when it opened a block
    for m in _TOKEN_RE.finditer(text):
        tok = m.group(0)
        if not cur:
            start_line, start_depth = line, depth
        line += tok.count("\n")
        if m.group(3):
            cur.append(" ")
            continue
        if m.group(1) or m.group(2):
            cur.append(tok)
            prev = tok
            continue
        cut = False
        if tok in "([":
            paren += 1
        elif tok in ")]":
            paren = max(0, paren - 1)
        elif tok == "{":
            is_block = paren == 0 and (prev in (")", ">", "else", "try", "finally", "do", "{", "}", ";", "") )
            braces.append(is_block)
            if is_block:
                depth += 1
                cut = True
            else:
                paren += 1             # hold the statement together until this brace closes
        elif tok == "}":
            was_block = braces.pop() if braces else True
            if was_block:
                depth = max(0, depth - 1)
                cut = paren == 0
            else:
                paren = max(0, paren - 1)
        elif tok == ";" and paren == 0:
            cut = True
        cur.append(tok)
        prev = tok
        if cut:
            stmt = "".join(cur).strip()
            if stmt:
                out.append((stmt, start_line, start_depth))
            cur = []
    tail = "".join(cur).strip()
    if tail:
        out.append((tail, start_line, start_depth))
    return out


def _split_top(s: str) -> list[str]:
    parts, cur, depth = [], [], 0
    for m in _TOKEN_RE.finditer(s):
        tok = m.group(0)
        if not m.group(1):
            if tok in "([{":
                depth += 1
            elif tok in ")]}":
                depth -= 1
            elif tok == "," and depth == 0:
                parts.append("".join(cur))
                cur = []
                continue
        cur.append(tok)
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _bindings(stmts: list[tuple[str, int, int]]) -> dict[str, str]:
    """Top-level names and what to write in their place."""
    found: dict[str, str] = {}
    seen: dict[str, int] = {}
    for stmt, _, depth in stmts:
        if depth != 0:
            continue
        # import{createHash as e,createHmac}from"crypto"   import*as e from"crypto"   import e from"crypto"
        m = re.match(rf"import\s*(.+?)\s*from\s*{_CRYPTO_MODULE}", stmt)
        if m:
            what = m.group(1).strip()
            star = re.fullmatch(r"\*\s*as\s+([\w$]+)", what)
            if star:
                found[star.group(1)] = "crypto"
            elif what.startswith("{"):
                for item in _split_top(what.strip("{} ")):
                    a = re.fullmatch(r"([\w$]+)(?:\s+as\s+([\w$]+))?", item)
                    if a:
                        found[a.group(2) or a.group(1)] = f"crypto.{a.group(1)}"
            elif re.fullmatch(r"[\w$]+", what):
                found[what] = "crypto"
            continue
        decl = re.match(r"(?:const|let|var)\b\s*(.*?);?$", stmt, re.S)
        if not decl:
            continue
        for item in _split_top(decl.group(1)):
            eq = re.match(r"([\w$]+)\s*=(?!=)\s*(.+)$", item, re.S)
            if eq:
                name, rhs = eq.group(1), eq.group(2).strip()
                seen[name] = seen.get(name, 0) + 1
                if re.fullmatch(rf"require\(\s*{_CRYPTO_MODULE}\s*\)", rhs):
                    found[name] = "crypto"
                elif _STRING_LITERAL_RE.match(rhs):
                    found[name] = rhs
                continue
            # const{createCipheriv:e,randomBytes}=require("node:crypto")
            ds = re.match(rf"\{{(.*)\}}\s*=\s*require\(\s*{_CRYPTO_MODULE}\s*\)$", item, re.S)
            if ds:
                for field in _split_top(ds.group(1)):
                    a = re.fullmatch(r"([\w$]+)(?:\s*:\s*([\w$]+))?", field)
                    if a:
                        found[a.group(2) or a.group(1)] = f"crypto.{a.group(1)}"
    code = " ".join(_strings_blanked(s) for s, _, _ in stmts)
    return {k: v for k, v in found.items() if seen.get(k, 1) == 1 and not _reassigned(k, code)}


def _strings_blanked(stmt: str) -> str:
    return "".join('""' if m.group(1) else m.group(0) for m in _TOKEN_RE.finditer(stmt))


def _reassigned(name: str, code: str) -> bool:
    """True when the file assigns to `name` anywhere other than in a declaration. A function that
    declares its own `n` is not a reassignment; a bare `n="sha256"` is, wherever it sits."""
    for m in re.finditer(rf"(?<![\w$.]){re.escape(name)}\s*(?:\*\*|<<|>>>?|[-+*/%|&^])?=(?![=>])", code):
        # Walk back to where this declaration or expression starts, stepping over balanced brackets.
        i, depth = m.start() - 1, 0
        while i >= 0:
            ch = code[i]
            if ch in ")]":
                depth += 1
            elif ch in "([":
                if depth == 0:
                    break
                depth -= 1
            elif ch in ";{}" and depth == 0:
                break
            i -= 1
        if not re.match(r"\s*(?:const|let|var)\b", code[i + 1:m.start()]):
            return True
    return False


def _names_bound_in(block: list[str]) -> set[str]:
    """Every name a block could have given a meaning of its own: parameters, locals, anything assigned."""
    names: set[str] = set()
    text = " ".join(block)
    for m in re.finditer(r"function\s*[\w$]*\s*\(([^)]*)\)|\(([^()]*)\)\s*=>|([\w$]+)\s*=>|catch\s*\(([^)]*)\)", text):
        names.update(re.findall(r"[A-Za-z_$][\w$]*", next(g for g in m.groups() if g is not None)))
    for m in re.finditer(r"\b(?:const|let|var)\b\s*", text):
        rest = text[m.end():]
        end = re.search(r";|\bof\b|\bin\b", rest)
        for item in _split_top(rest[: end.start()] if end else rest):
            target = re.split(r"=(?!=|>)", item, maxsplit=1)[0]
            names.update(re.findall(r"[A-Za-z_$][\w$]*", re.sub(r"[\w$]+\s*:", "", target)))
    names.update(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:[+\-*/|&^]?=)(?![=>])", text))
    return names


def _rewrite(stmt: str, bindings: dict[str, str], shadowed: set[str]) -> str:
    out, prev = [], ""
    toks = list(_TOKEN_RE.finditer(stmt))
    for i, m in enumerate(toks):
        tok = m.group(0)
        if m.group(2) and tok in bindings and tok not in shadowed and prev != ".":
            nxt = next((t.group(0) for t in toks[i + 1:] if not t.group(3)), "")
            is_key = nxt == ":" and prev in ("{", ",")
            is_decl = nxt == "=" and prev in ("const", "let", "var", ",")
            if not is_key and not is_decl:
                tok = bindings[tok]
        if not m.group(3):
            prev = m.group(0)
        out.append(tok)
    return "".join(out)


def expand(text: str) -> tuple[list[str], list[int]]:
    """Statements with top-level crypto names put back, and the source line of each."""
    stmts = _statements(text)
    if not stmts:
        return text.splitlines(), list(range(1, len(text.splitlines()) + 1))
    bindings = _bindings(stmts)
    lines, line_map = [], []
    i = 0
    while i < len(stmts):
        stmt, src, depth = stmts[i]
        if depth == 0 and not stmt.endswith("{"):
            defines = re.search(rf"require\(\s*{_CRYPTO_MODULE}\s*\)|from\s*{_CRYPTO_MODULE}", stmt)
            lines.append(stmt if defines else _rewrite(stmt, bindings, set()))
            line_map.append(src)
            i += 1
            continue
        # A block: everything from this header until the depth comes back to where it started.
        j = i + 1
        while j < len(stmts) and stmts[j][2] > depth:
            j += 1
        block = stmts[i:j]
        shadowed = _names_bound_in([s for s, _, _ in block]) if bindings else set()
        for s, ln, _ in block:
            lines.append(_rewrite(s, bindings, shadowed))
            line_map.append(ln)
        i = j
    return lines, line_map
