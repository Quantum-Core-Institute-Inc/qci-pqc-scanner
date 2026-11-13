# Copyright (c) 2026 Quantum Core Institute Inc. MIT License.
"""TLS as configured: which protocol versions are enabled and which cipher suites are named.

A cipher suite is the unit a migration works in. "This listener offers a weak cipher" tells an
owner to look; `TLS_RSA_WITH_3DES_EDE_CBC_SHA on line 21` tells them what to remove. Each suite a
configuration names becomes one finding, under its IANA name whether the file used that or the
OpenSSL spelling (`DES-CBC3-SHA`).

Three rules keep this from reporting things that aren't configuration:

- An OpenSSL-style name counts only on a line that sets ciphers. `AES128-SHA` is too ordinary a
  string to trust anywhere else.
- In source code, a suite name in a string counts only when the statement hands it to something
  that sets ciphers, or when the line is nothing but that string (an item in a list). A name in a
  log message is a name in a log message.
- A version or suite a directive turns off (`-TLSv1`, `!RC4`, `no-tlsv11`) is not reported.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import QuantumStatus


@dataclass(frozen=True)
class TlsHit:
    family: str            # "TLS-1.1" or an IANA suite name
    status: QuantumStatus
    weak: bool
    role: str              # "protocol" or "cipher-suite"
    param: str = ""


# --- cipher suites ---------------------------------------------------------------------------

_KX = {"": "RSA", "ECDHE-RSA-": "ECDHE_RSA", "ECDHE-ECDSA-": "ECDHE_ECDSA", "DHE-RSA-": "DHE_RSA", "DHE-DSS-": "DHE_DSS"}
_COMMON = {
    "AES128-SHA": "AES_128_CBC_SHA", "AES256-SHA": "AES_256_CBC_SHA",
    "AES128-GCM-SHA256": "AES_128_GCM_SHA256", "AES256-GCM-SHA384": "AES_256_GCM_SHA384",
    "DES-CBC3-SHA": "3DES_EDE_CBC_SHA",
}
_BY_KX = {
    "RSA": {**_COMMON, "AES128-SHA256": "AES_128_CBC_SHA256", "AES256-SHA256": "AES_256_CBC_SHA256",
            "RC4-SHA": "RC4_128_SHA", "RC4-MD5": "RC4_128_MD5", "NULL-SHA": "NULL_SHA", "NULL-MD5": "NULL_MD5",
            "NULL-SHA256": "NULL_SHA256", "DES-CBC-SHA": "DES_CBC_SHA", "CAMELLIA128-SHA": "CAMELLIA_128_CBC_SHA",
            "CAMELLIA256-SHA": "CAMELLIA_256_CBC_SHA", "AES128-CCM": "AES_128_CCM", "AES256-CCM": "AES_256_CCM"},
    "DHE_RSA": {**_COMMON, "AES128-SHA256": "AES_128_CBC_SHA256", "AES256-SHA256": "AES_256_CBC_SHA256",
                "CHACHA20-POLY1305": "CHACHA20_POLY1305_SHA256", "CAMELLIA128-SHA": "CAMELLIA_128_CBC_SHA",
                "CAMELLIA256-SHA": "CAMELLIA_256_CBC_SHA", "AES128-CCM": "AES_128_CCM", "AES256-CCM": "AES_256_CCM"},
    "DHE_DSS": {**_COMMON, "AES128-SHA256": "AES_128_CBC_SHA256", "AES256-SHA256": "AES_256_CBC_SHA256"},
    "ECDHE_RSA": {**_COMMON, "AES128-SHA256": "AES_128_CBC_SHA256", "AES256-SHA384": "AES_256_CBC_SHA384",
                  "RC4-SHA": "RC4_128_SHA", "CHACHA20-POLY1305": "CHACHA20_POLY1305_SHA256", "NULL-SHA": "NULL_SHA"},
    "ECDHE_ECDSA": {**_COMMON, "AES128-SHA256": "AES_128_CBC_SHA256", "AES256-SHA384": "AES_256_CBC_SHA384",
                    "RC4-SHA": "RC4_128_SHA", "CHACHA20-POLY1305": "CHACHA20_POLY1305_SHA256", "NULL-SHA": "NULL_SHA",
                    "AES128-CCM": "AES_128_CCM", "AES256-CCM": "AES_256_CCM"},
}
OPENSSL_TO_IANA = {
    f"{prefix}{body}": f"TLS_{kx}_WITH_{iana}"
    for prefix, kx in _KX.items() for body, iana in _BY_KX[kx].items()
}
OPENSSL_TO_IANA["EDH-RSA-DES-CBC3-SHA"] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"   # the pre-1.0 spelling
TLS13_SUITES = {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256"}

_IANA_RE = re.compile(r"(?<![A-Za-z0-9_])(?:TLS|SSL)_[A-Z0-9]+(?:_[A-Z0-9]+)*_WITH_[A-Z0-9]+(?:_[A-Z0-9]+)*(?![A-Za-z0-9_])")
_TLS13_RE = re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(sorted(TLS13_SUITES, key=len, reverse=True)) + r")(?![A-Za-z0-9_])")
_OPENSSL_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_+-])([!+-]?)([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)(?![A-Za-z0-9_-])")
# A directive, key or call that sets the cipher list.
_SETS_CIPHERS_RE = re.compile(
    r"ssl_ciphers|ssl_conf_command\s+Ciphersuites|SSLCipherSuite|SSLProxyCipherSuite|bind-ciphers|server-ciphers|\bciphers(?:uites)?\b\s*[:=(]?"
    r"|CipherString|Ciphersuites\s*=|cipher[-_.]?suites?|cipher_list|set_ciphers|setEnabledCipherSuites|CipherSuites\s*[:=]"
    r"|tls[-_.]?ciphers?|ssl[-_.]?ciphers?|honorCipherOrder", re.I)
# In source code the bar is higher: a call or an assignment that sets ciphers, not a name that
# happens to contain the word.
_SETS_CIPHERS_IN_CODE_RE = re.compile(
    r"set_ciphers\s*\(|set_cipher_list\s*\(|set_ciphersuites\s*\(|setEnabledCipherSuites\s*\(|\.cipherSuites\s*\("
    r"|\b(?:CipherSuites|cipherSuites|cipher_suites|ciphers|ciphersuites|CipherString|Ciphersuites)\b\s*(?::=|[:=])(?!=)"
    r"|SSL_CTX_set1?_\w*cipher\w*\s*\(|SSL_set_cipher_list\s*\(|tls[-_.]?ciphers?\s*[:=]|ssl[-_.]?ciphers?\s*[:=]", re.I)
# A library's own constant: tls.TLS_AES_128_GCM_SHA256 (Go), CipherSuite.TLS_... (OkHttp, .NET).
_QUALIFIED_RE = re.compile(r"(?:\btls|CipherSuite|TlsCipherSuite|CipherSuites)\.$")
_DECLARES_RE = re.compile(r"^\s*(?:public\s+|private\s+|export\s+|static\s+)*(?:enum|class|interface|struct|type|typedef)\b")
_REPORTS_RE = re.compile(
    r"\b(?:log(?:ger|ging)?|print(?:f|ln)?|console|fmt\.(?:Print|Sprint|Errorf)|System\.(?:out|err)|puts|echo|raise|throw|assert\w*|describe|expect)\b",
    re.I)
_SOURCE_EXTS = {".py", ".java", ".kt", ".scala", ".go", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".c", ".h", ".cc",
                ".cpp", ".hpp", ".cs", ".rs", ".rb", ".php", ".swift"}
_ONLY_A_STRING_RE = re.compile(r"""^\s*["'`][\w-]+["'`]\s*,?\s*$""")


def suite_status(iana: str) -> tuple[QuantumStatus, bool]:
    """Quantum status from the key exchange; weak when the suite is broken classically as well."""
    weak = bool(re.search(r"_(?:3DES|DES|RC4|NULL|EXPORT|anon)_|_MD5$|_NULL_", iana))
    if "_WITH_" not in iana:                     # TLS 1.3: key exchange is negotiated separately
        return QuantumStatus.SAFE_SYMMETRIC, weak
    return (QuantumStatus.WEAK if weak else QuantumStatus.VULNERABLE), weak


def suites_in(code: str, suffix: str = "") -> list[str]:
    """IANA names of the cipher suites this line configures, in the order written."""
    is_source = suffix.lower() in _SOURCE_EXTS
    sets = bool((_SETS_CIPHERS_IN_CODE_RE if is_source else _SETS_CIPHERS_RE).search(code))
    if is_source and _DECLARES_RE.match(code):
        return []                                 # a type that names suites declares them, it doesn't enable them
    found: list[str] = []

    def add(name: str) -> None:
        if name not in found:
            found.append(name)

    if is_source and _REPORTS_RE.search(code):
        return []                                 # a line that prints or logs is not configuration
    for m in list(_IANA_RE.finditer(code)) + list(_TLS13_RE.finditer(code)):
        name = m.group(0)
        before = code[: m.start()]
        quoted = before.count('"') % 2 == 1 or before.count("'") % 2 == 1 or before.count("`") % 2 == 1
        if is_source and quoted and not (sets or _ONLY_A_STRING_RE.match(code)):
            continue                              # a name in a string that nothing hands to TLS
        if is_source and not quoted and not (sets or _QUALIFIED_RE.search(before)):
            continue                              # somebody's own identifier that looks like a suite
        if before.rstrip().endswith("!"):
            continue
        add("TLS_" + name[4:] if name.startswith("SSL_") else name)
    if sets:
        for m in _OPENSSL_TOKEN_RE.finditer(code):
            if m.group(1) in ("!", "-"):
                continue                          # removed from the list, not offered
            iana = OPENSSL_TO_IANA.get(m.group(2))
            if iana:
                add(iana)
    return found


# --- protocol versions -----------------------------------------------------------------------

_VERSION_WORD = r"(?:TLSv?1(?:[._][0-3])?|SSLv[23])"
_WORD_TO_FAMILY = {"TLSV1": "TLS-1.0", "TLSV1.0": "TLS-1.0", "TLSV1_0": "TLS-1.0", "TLS1": "TLS-1.0", "TLS1.0": "TLS-1.0",
                   "TLSV1.1": "TLS-1.1", "TLSV1_1": "TLS-1.1", "TLS1.1": "TLS-1.1", "TLS1_1": "TLS-1.1",
                   "TLSV1.2": "TLS-1.2", "TLSV1_2": "TLS-1.2", "TLS1.2": "TLS-1.2", "TLS1_2": "TLS-1.2",
                   "TLSV1.3": "TLS-1.3", "TLSV1_3": "TLS-1.3", "TLS1.3": "TLS-1.3", "TLS1_3": "TLS-1.3",
                   "SSLV3": "SSL-3.0", "SSLV2": "SSL-2.0"}
# Directives and keys whose value is a list of enabled versions, or a floor or ceiling.
_VERSION_KEY_RE = re.compile(
    r"SSLProtocol|SSLProxyProtocol|enabled[-_.]?protocols|ssl[-_.]protocols?\b|tls[-_.]?(?:min|max|minimum|maximum)?[-_.]?versions?"
    r"|ssl-(?:min|max)-ver|MinProtocol|MaxProtocol|min(?:imum)?[-_.]?(?:tls|protocol)[-_.]?version|minVersion|maxVersion"
    r"|setEnabledProtocols|setProtocols|SSLContext\.getInstance|ssl_version|tls_version|minimum_version|maximum_version", re.I)
_VERSION_TOKEN_RE = re.compile(rf"(?<![A-Za-z0-9_.])([+-]?)({_VERSION_WORD})(?![\d.A-Za-z_])", re.I)
# Constants that name a version on their own.
_CONSTANTS = [
    (re.compile(r"\btls\.VersionTLS1([0-3])\b"), lambda m: f"TLS-1.{m.group(1)}"),                       # Go
    (re.compile(r"\btls\.VersionSSL30\b"), lambda m: "SSL-3.0"),
    (re.compile(r"\bTLS1_VERSION\b"), lambda m: "TLS-1.0"),                                              # OpenSSL
    (re.compile(r"\bTLS1_([123])_VERSION\b"), lambda m: f"TLS-1.{m.group(1)}"),
    (re.compile(r"\bSSL3_VERSION\b"), lambda m: "SSL-3.0"),
    (re.compile(r"\bTLSVersion\.TLSv1(?:_([123]))?\b"), lambda m: f"TLS-1.{m.group(1) or 0}"),           # Python ssl
    (re.compile(r"\bPROTOCOL_TLSv1(?:_([12]))?\b"), lambda m: f"TLS-1.{m.group(1) or 0}"),
    (re.compile(r"\bSslProtocols\.Tls(1[123])?\b"), lambda m: f"TLS-1.{(m.group(1) or '10')[1]}"),      # .NET
    (re.compile(r"\bSslProtocols\.Ssl3\b"), lambda m: "SSL-3.0"),
]
_DISABLES_RE = re.compile(r"\bno-(?:tlsv1[0-3]?|sslv3)\b|SSL_OP_NO_|OP_NO_|disabledAlgorithms|options\s*\|=", re.I)


def version_status(family: str) -> tuple[QuantumStatus, bool]:
    if family in {"TLS-1.0", "TLS-1.1", "SSL-3.0", "SSL-2.0"}:
        return QuantumStatus.WEAK, True
    return QuantumStatus.SAFE_SYMMETRIC, False


def versions_in(code: str) -> list[str]:
    """Protocol versions this line enables: listed, or set as a floor or ceiling."""
    if _DISABLES_RE.search(code):
        return []
    found: list[str] = []
    for pat, name in _CONSTANTS:
        for m in pat.finditer(code):
            fam = name(m)
            if fam not in found:
                found.append(fam)
    if _VERSION_KEY_RE.search(code):
        for m in _VERSION_TOKEN_RE.finditer(code):
            if m.group(1) == "-":
                continue                          # Apache: -TLSv1 turns it off
            fam = _WORD_TO_FAMILY.get(m.group(2).upper())
            if fam and fam not in found:
                found.append(fam)
    return found


def hits_in(code: str, suffix: str = "") -> list[TlsHit]:
    out = []
    for fam in versions_in(code):
        status, weak = version_status(fam)
        out.append(TlsHit(fam, status, weak, "protocol", fam.replace("TLS-", "TLSv").replace("SSL-", "SSLv")))
    for name in suites_in(code, suffix):
        status, weak = suite_status(name)
        out.append(TlsHit(name, status, weak, "cipher-suite", name))
    return out
