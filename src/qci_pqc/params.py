# Copyright (c) 2026 Quantum Core Institute Inc. MIT License.
"""Classical parameters of a finding: key size, curve, cipher mode, hash.

The pattern scanner matches one line. The parameter a migration ticket needs is often somewhere
else: on the next line of the same call, behind a constant, or set on the object the call returns.
This module looks in three places, in this order, and stops at the first that answers:

1. The statement: the matched line plus its continuation lines, until the brackets balance.
2. Names the statement uses, when the file defines them exactly once.
3. Later statements on the object the statement creates.

A parameter is only reported when exactly one value is in view. Two candidate values mean the
scanner does not know, and it says nothing.
"""
from __future__ import annotations

import re

MODES = ("ECB", "CBC", "GCM", "CTR", "CFB", "OFB", "CCM", "XTS")
_MODE_ALT = "|".join(MODES)

_HASHES = [
    (r"sha3[-_]?(224|256|384|512)", lambda m: f"SHA3-{m.group(1)}"),
    (r"sha[-_]?(224|256|384|512)", lambda m: f"SHA-{m.group(1)}"),
    (r"sha[-_]?1(?![0-9])", lambda m: "SHA-1"),
    (r"md5", lambda m: "MD5"),
]
_HASH_RE = re.compile("|".join(f"(?:{p})" for p, _ in _HASHES), re.I)

_CURVE_RE = re.compile(
    r"(?:secp|nistp|nist_?p|prime|P[-_]?|elliptic\.P|ansip|brainpoolP)(256|384|521)(?:r1|v1|k1)?(?![0-9])", re.I)

_MODP = {"1": 768, "2": 1024, "5": 1536, "14": 2048, "15": 3072, "16": 4096, "17": 6144, "18": 8192}

_KEYWORDS = frozenset(
    "if else for while return new const let var val def func function class struct static final public private "
    "protected using import from package int long byte char void string String bool boolean true false null nil None "
    "this self try catch throw throws await async err error".split())

_SIZE_SITES = [
    r"modulusLength\s*:\s*([\w.\[\]\"']+)",
    r"\bkey_?size\s*[=:]\s*([\w.\[\]\"']+)",
    r"\bKeySize\s*=\s*([\w.]+)",
    r"\bbits\s*=\s*([\w.]+)\s*[,)]",
    r"\b(?:RSA|DSA)\.generate\(\s*([\w.]+)",
    r"\b(?:rsa|RSA|dsa|DSA)\.(?:GenerateKey|GenerateMultiPrimeKey)\(\s*[\w.]+\s*,\s*([\w.]+)",
    r"\b(?:RSA|DSA|RSACng|DSACng|RSAOpenSsl)\.Create\(\s*([\w.]+)\s*\)",
    r"\bnew\s+(?:RSACryptoServiceProvider|DSACryptoServiceProvider|RSACng)\(\s*([\w.]+)\s*\)",
    r"\b(?:RSA|DSA)_generate_(?:key|parameters)(?:_ex)?\(\s*[\w&*]+\s*,\s*([\w.]+)",
    r"\bEVP_RSA_gen\(\s*([\w.]+)\s*\)",
    r"set_(?:rsa_keygen|dsa_paramgen|dh_paramgen_prime)_(?:bits|len)\(\s*[\w&*]+\s*,\s*([\w.]+)",
    r"default-dh-param\s+(\d+)",
    r"\b(?:RSA|DSA|DH)_(\d{4})\b",
    r"\.initialize\(\s*([\w.]+)\s*[,)]",
    r"\bDHParameterSpec\([^;]*?,\s*([\w.]+)\s*\)",
    r"\bgenerate_parameters\([^)]*?key_size\s*=\s*([\w.]+)",
]
_SIZE_SITE_RE = [re.compile(p) for p in _SIZE_SITES]
_NAMED_SIZE_RE = re.compile(r"modp(\d{1,2})\b|ffdhe(\d{4})\b|\bL(\d{4})N\d{3}\b|group(\d{1,2})[-_]sha", re.I)
_PQ_LEVEL_RE = {"ML-KEM": re.compile(r"ML[-_]?KEM[-_]?(512|768|1024)(?![0-9])|Kyber(512|768|1024)", re.I),
                "ML-DSA": re.compile(r"ML[-_]?DSA[-_]?(44|65|87)(?![0-9])", re.I)}

_KEY_BYTES_RE = re.compile(
    r"(?:urandom|token_bytes|get_random_bytes|randomBytes|GetBytes|random_bytes|RAND_bytes|make\(\s*\[\]byte\s*,|"
    r"new\s+byte\s*\[|Buffer\.alloc|bytes\()\s*\(?\s*(16|24|32)\b|\[\s*(16|24|32)\s*\]\s*byte|unsigned\s+char\s+\w+\[\s*(16|24|32)\s*\]")
_KEY_BITS_RE = re.compile(r"(?:bit_length|KeySize|keysize|key_size|\.init)\s*[=(:]\s*(128|192|256)\b")
_AES_NAME_RE = re.compile(rf"aes[-_/]?(128|192|256)(?:[-_/]?({_MODE_ALT}))?(?![0-9a-z])", re.I)
_MODE_SITES = re.compile(
    rf"cipher\.New({_MODE_ALT})"
    rf"|(?:modes\.|MODE_|CipherMode\.|AES/|DESede/|DES/|TripleDES/|des[-_]ede3?[-_]|des[-_]|_mode\s*=\s*[\"']?)({_MODE_ALT})\b"
    rf"|\b(?:AES|Aes)({_MODE_ALT})\b|EVP_[a-z0-9]+(?:_[a-z0-9]+)*_({_MODE_ALT})\b|[\"'][\w-]*-({_MODE_ALT})[\"']", re.I)


def statement(lines: list[str], idx: int, limit: int = 8) -> str:
    out, depth = [], 0
    for line in lines[idx: idx + limit]:
        code = _strip_comment(line)
        out.append(code.strip())
        depth += sum(code.count(c) for c in "([{") - sum(code.count(c) for c in ")]}")
        if depth <= 0:
            break
    return " ".join(out)


def _strip_comment(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith(("//", "#", "/*", "*")):
        return ""
    for mark in (" //", "\t//", " # ", "\t# "):
        if mark in line:
            line = line.split(mark, 1)[0]
    return line


def _assigned_name(stmt: str) -> str | None:
    m = re.match(r"\s*(?:var\s+)?(\w+)\s+[\w.\[\]*]+\s*$", stmt)
    if m and stmt.strip().startswith("var "):
        return m.group(1)
    m = re.search(r"([A-Za-z_]\w*)\s*(?:,\s*\w+\s*)?(?::=|=)(?![=>])", stmt)
    if m and m.group(1) not in _KEYWORDS:
        return m.group(1)
    return None


def definitions(name: str, lines: list[str]) -> list[str]:
    found: list[str] = []
    ident = re.escape(name)
    assign = re.compile(
        rf"(?<![\w.])(?:(?:const|let|var|val|final|static|public|private|protected|readonly)\s+)*(?:[\w.<>\[\]*]+\s+\**)?{ident}(?:\[\w*\])?"
        rf"(?:\s*:\s*[\w.<>\[\]| ]+?)?\s*(?::=|=)(?![=>])\s*(.+)")
    func = re.compile(rf"(?:\b(?:def|func|function)\s+{ident}\s*\(|^[\w\s.<>\[\]*]*?\b{ident}\s*\([^;]*\)\s*(?:[\w.<>\[\]* ]+)?\{{)")
    for i, line in enumerate(lines):
        code = _strip_comment(line)
        if name not in code:
            continue
        m = assign.search(code)
        if m and not re.match(r"\s*(?:if|while|for|return)\b", code):
            found.append(statement(lines, i)[m.start():] if m.group(1).rstrip().endswith(("(", "{", ",")) else m.group(1))
            continue
        if func.search(code) and not re.search(rf"[=(,]\s*{ident}\s*\(", code):
            returns = []
            for body in lines[i: i + 12]:
                r = re.search(r"\breturn\s+(.+)", _strip_comment(body))
                if r:
                    returns.append(r.group(1))
                if body.strip() in ("}", "") and body is not lines[i] and returns:
                    break
            if len(returns) == 1:
                found.append(returns[0])
            elif returns:
                found.extend(returns)
    return found


def _field(key: str, lines: list[str]) -> str | None:
    pat = re.compile(rf"[\"']?\b{re.escape(key)}\b[\"']?\s*(?::|=>)\s*([\w.\"'()-]+)")
    vals = {m.group(1) for line in lines for m in pat.finditer(_strip_comment(line))}
    return vals.pop() if len(vals) == 1 else None


def resolve(token: str, lines: list[str], depth: int = 2) -> str | None:
    token = token.strip()
    if not token or re.fullmatch(r"[\d_]+|[\"'].*[\"']", token):
        return token.strip("\"'")
    m = re.fullmatch(r"[\w.]+\[\s*[\"'](\w+)[\"']\s*\]", token) or re.fullmatch(r"[A-Za-z_]\w*\.(\w+)", token)
    if m:
        val = _field(m.group(1), lines)
        if val is not None:
            return resolve(val, lines, depth - 1) if depth > 0 else val
    name = token.split("(")[0].split("[")[0].split(".")[-1]
    if not re.fullmatch(r"[A-Za-z_]\w*", name) or name in _KEYWORDS:
        return token
    defs = definitions(name, lines)
    if len(defs) != 1:
        return token if not defs else None
    rhs = defs[0].strip().rstrip(";")
    inner = re.fullmatch(r"([A-Za-z_][\w.]*)(?:\(\))?", rhs)
    if inner and depth > 0 and inner.group(1) != name:
        again = resolve(rhs, lines, depth - 1)
        return again if again is not None else rhs
    return rhs


def _split_args(s: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    out.append(cur.strip())
    return out


def call_site_args(name: str, lines: list[str], idx: int) -> list[str]:
    word = re.compile(rf"(?<![\w.]){re.escape(name)}\b")
    for j in range(idx, max(-1, idx - 60), -1):
        head = _strip_comment(lines[j])
        if "(" not in head or not word.search(head) or not re.search(r"[{:]\s*$|=>", head.rstrip()):
            continue
        m = re.search(r"([A-Za-z_]\w*)\s*\(", re.sub(r"^\s*(?:def|func|function|public|private|protected|static|async|final)\b", "", head))
        if not m or m.group(1) in _KEYWORDS:
            continue
        fname = m.group(1)
        inner = head[head.index("(", m.start()) + 1: head.rindex(")")] if ")" in head else ""
        pos = next((k for k, a in enumerate(_split_args(inner)) if word.search(a)), None)
        if pos is None:
            continue
        call = re.compile(rf"(?<![\w]){re.escape(fname)}\s*\(")
        args = []
        for k, line in enumerate(lines):
            code = _strip_comment(line)
            if k == j:
                continue
            for c in call.finditer(code):
                stmt = statement(lines, k)
                start = stmt.find(c.group(0))
                if start < 0:
                    continue
                body, depth = "", 0
                for ch in stmt[start + len(c.group(0)):]:
                    if ch in "([{":
                        depth += 1
                    elif ch in ")]}":
                        if depth == 0:
                            break
                        depth -= 1
                    body += ch
                parts = _split_args(body)
                if pos < len(parts) and parts[pos]:
                    args.append(parts[pos])
        return args
    return []


def _inline(rhs: str, lines: list[str]) -> str:
    def repl(m):
        tok = m.group(0)
        last = tok.split(".")[-1]
        if last in _KEYWORDS or len(definitions(last, lines)) != 1:
            return tok
        val = definitions(last, lines)[0].strip().rstrip(";")
        return val if re.fullmatch(r"\d+|[\"'][^\"']*[\"']", val) else tok
    return re.sub(r"(?<![\w.\"'])[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?![\w(\"'.])", repl, rhs)


def _context(stmt: str, lines: list[str], skip: str | None, idx: int = 0) -> str:
    parts = []
    seen = set()
    for tok in re.findall(r"[A-Za-z_]\w*(?:\.\w+|\[\s*[\"']\w+[\"']\s*\])?", stmt):
        base = tok.split(".")[0].split("[")[0]
        if tok in seen or base in _KEYWORDS or base == skip:
            continue
        seen.add(tok)
        val = None
        if "." in tok or "[" in tok:
            m = re.search(r"\.(\w+)$|[\"'](\w+)[\"']", tok)
            field = _field(m.group(1) or m.group(2), lines) if m else None
            if field is not None:
                val = resolve(field, lines, 1) or field
        if val is None:
            n = len(definitions(base, lines))
            if n == 1:
                val = resolve(base, lines)
                val = _inline(val, lines) if val else val
            elif n == 0:
                passed = {resolve(a, lines) or a for a in call_site_args(base, lines, idx)}
                if len(passed) == 1:
                    val = passed.pop()
        if val and val != tok and val != base:
            parts.append(val)
    return " ; ".join(parts)


def _followups(name: str | None, lines: list[str], idx: int, span: int = 40) -> str:
    if not name:
        return ""
    pat = re.compile(rf"(?<![\w.]){re.escape(name)}\b")
    out = []
    for j in range(idx + 1, min(len(lines), idx + 1 + span)):
        code = _strip_comment(lines[j])
        if pat.search(code):
            out.append(statement(lines, j, 4))
    return _inline(" ; ".join(out), lines)


def _one(values) -> str | None:
    vals = {v for v in values if v}
    return vals.pop() if len(vals) == 1 else None


def hashes_in(text: str) -> set[str]:
    out = set()
    for m in _HASH_RE.finditer(text):
        for pat, name in _HASHES:
            mm = re.fullmatch(pat, m.group(0), re.I)
            if mm:
                out.add(name(mm))
                break
    return out


def curves_in(text: str) -> set[str]:
    return {f"P-{m.group(1)}" for m in _CURVE_RE.finditer(text)}


def modes_in(text: str) -> set[str]:
    return {next(g for g in m.groups() if g).upper() for m in _MODE_SITES.finditer(text)}


def _plausible_size(v: str | None, family: str) -> str | None:
    if not v or not v.isdigit():
        return None
    n = int(v)
    return v if 512 <= n <= 16384 and n % 8 == 0 else None


def sizes_in(text: str, lines: list[str], family: str, idx: int = 0) -> set[str]:
    out = set()
    for pat in _SIZE_SITE_RE:
        for m in pat.finditer(text):
            val = resolve(m.group(1), lines)
            if val is None:
                continue
            if val == m.group(1).strip() and re.fullmatch(r"[A-Za-z_]\w*", val):
                passed = {resolve(a, lines) or a for a in call_site_args(val, lines, idx)}
                if len(passed) != 1:
                    continue
                val = passed.pop()
            nums = re.findall(r"(?<![\w.])(\d{3,5})(?![\w.])", val)
            if len(set(nums)) == 1 and _plausible_size(nums[0], family):
                out.add(nums[0])
    for m in _NAMED_SIZE_RE.finditer(text):
        if m.group(1) and m.group(1) in _MODP:
            out.add(str(_MODP[m.group(1)]))
        elif m.group(4) and m.group(4) in _MODP:
            out.add(str(_MODP[m.group(4)]))
        elif m.group(2) or m.group(3):
            out.add(m.group(2) or m.group(3))
    return out


_AES_KEY_ARG_RE = re.compile(
    r"(?:algorithms\.AES(?:128|256)?|AES\.new|AESGCM|AESCCM|AESSIV|aes\.NewCipher|new\s+Aes(?:Gcm|Ccm)|new\s+SecretKeySpec|"
    r"createCipheriv\(\s*[^,]+,|createDecipheriv\(\s*[^,]+,)\s*\(?\s*([A-Za-z_][\w.]*)")


def aes_bits_in(text: str) -> set[str]:
    out = {m.group(1) for m in _AES_NAME_RE.finditer(text)}
    out |= {m.group(1) for m in _KEY_BITS_RE.finditer(text)}
    return out


def aes_key_bits(stmt: str, lines: list[str]) -> set[str]:
    out = set()
    for m in _AES_KEY_ARG_RE.finditer(stmt):
        rhs = resolve(m.group(1), lines)
        if not rhs or rhs == m.group(1):
            continue
        rhs = _inline(rhs, lines)
        out |= aes_bits_in(rhs)
        for k in _KEY_BYTES_RE.finditer(rhs):
            out.add(str(int(next(g for g in k.groups() if g)) * 8))
    return out


def modes_in_aes(text: str) -> set[str]:
    return {m.group(1).upper() for m in re.finditer(
        rf"(?:AES/|aes[-_](?:128|192|256)[-_]|AES\.MODE_|\bAes|\bAES)({_MODE_ALT})\b", text, re.I)}


def modes_in_des(text: str) -> set[str]:
    return {m.group(1).upper() for m in re.finditer(
        rf"(?:DESede/|DES/|TripleDES/|des[-_]ede3?[-_]|DES3\.MODE_|DES\.MODE_)({_MODE_ALT})\b", text, re.I)}


def refine(family: str, param: str, lines: list[str], idx: int) -> str:
    fam = family.upper()
    given = param
    if param.upper() == fam:
        param = ""
    stmt = statement(lines, idx)
    if not stmt.strip():
        return given
    name = _assigned_name(stmt)
    cache: dict[str, str] = {}

    def view(k: str) -> str:
        if k not in cache:
            if k == "ctx":
                cache[k] = _context(stmt, lines, name, idx)
            elif k == "later":
                cache[k] = _followups(name, lines, idx)
            elif k == "later_ctx":
                cache[k] = _context(view("later"), lines, name, idx) if view("later") else ""
            else:
                cache[k] = "\n".join(_strip_comment(x) for x in lines)
        return cache[k]

    def near(find) -> str | None:
        if find(stmt):
            return _one(find(stmt))
        for k in ("ctx", "later", "later_ctx"):
            got = find(view(k))
            if got:
                return _one(got)
        return None

    if fam in {"RSA", "DSA", "DH"}:
        if param.isdigit():
            return param
        size = near(lambda s: sizes_in(s, lines, fam, idx))
        return size or given

    if fam in {"ECDSA", "ECDH", "ECC-P-256", "ECC-P-384", "EC"}:
        if param.upper().startswith("P-"):
            return param
        return near(curves_in) or given

    if fam in {"HMAC", "PBKDF2"}:
        return param or near(hashes_in) or given

    if fam in {"3DES", "DES"}:
        return param or near(modes_in) or _one(modes_in_des(view("file"))) or given

    if fam in _PQ_LEVEL_RE:
        level = near(lambda s: {next(g for g in m.groups() if g) for m in _PQ_LEVEL_RE[fam].finditer(s)})
        return f"{fam}-{level}" if level else given

    if fam == "AES" or fam.startswith("AES-"):
        size = next((p for p in param.split("-") if p in ("128", "192", "256")), "")
        mode = next((p for p in param.upper().split("-") if p in MODES), "")
        if not mode and fam.startswith("AES-") and fam[4:] in MODES:
            mode = fam[4:]
        size = _one(aes_bits_in(stmt)) or _one(aes_key_bits(stmt, lines)) or near(aes_bits_in) or size
        if not mode:
            mode = near(modes_in) or _one(modes_in_aes(view("file"))) or ""
        return "-".join(x for x in (size, mode) if x) or given

    return given
