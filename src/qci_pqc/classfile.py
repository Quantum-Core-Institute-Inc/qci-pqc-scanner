# Copyright (c) 2026 Quantum Core Institute Inc. MIT License.
"""What a compiled Java class asks the JCA for.

Source patterns do not survive compilation, but the calls do. `MessageDigest.getInstance("SHA-1")`
compiles to a string constant pushed onto the stack and a call to a method the constant pool names
in full, whatever an obfuscator did to the class around it. This module walks each method's
bytecode and reads exactly that: a constant, then the JCA call that takes it.

- An algorithm name counts only as the argument of a JCA call. A string constant that merely looks
  like one (`"EC"` as a country code) is not a finding.
- Only a constant pushed immediately before the call counts. A name assembled at run time, read
  from configuration or passed in is not a constant, and nothing is reported for it.
- Key size and curve come from the same place: `initialize(1024)`, `init(128)`,
  `new ECGenParameterSpec("secp256r1")`.

The parser reads the class file format directly (JVMS chapter 4) and needs no JDK.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from .models import QuantumStatus

_FIXED = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}

# Operand bytes per opcode; everything not listed takes none. tableswitch, lookupswitch and wide
# are variable and handled where they occur.
_OPERANDS = {16: 1, 17: 2, 18: 1, 19: 2, 20: 2, 132: 2, 167: 2, 168: 2, 169: 1, 185: 4, 186: 4, 187: 2, 188: 1,
             189: 2, 192: 2, 193: 2, 197: 3, 198: 2, 199: 2, 200: 4, 201: 4}
_OPERANDS.update({op: 1 for op in list(range(21, 26)) + list(range(54, 59))})
_OPERANDS.update({op: 2 for op in list(range(153, 167)) + list(range(178, 185))})
_INVOKES = {182, 183, 184, 185}


@dataclass
class Call:
    """One JCA call with constant arguments: `KeyPairGenerator.initialize(1024)`."""
    owner: str            # java/security/MessageDigest
    name: str             # getInstance
    method: str           # the method of the class the call is in
    strings: list[str] = field(default_factory=list)
    ints: list[int] = field(default_factory=list)


@dataclass
class ClassInfo:
    name: str = ""
    calls: list[Call] = field(default_factory=list)


def _constant_pool(data: bytes):
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return None, 0
    count = struct.unpack_from(">H", data, 8)[0]
    pool: dict[int, tuple] = {}
    i, n = 10, 1
    while n < count:
        if i >= len(data):
            return None, 0
        tag = data[i]
        i += 1
        if tag == 1:
            length = struct.unpack_from(">H", data, i)[0]
            pool[n] = (1, data[i + 2:i + 2 + length].decode("utf-8", errors="replace"))
            i += 2 + length
        elif tag == 3:
            pool[n] = (3, struct.unpack_from(">i", data, i)[0])
            i += 4
        elif tag in (7, 8):
            pool[n] = (tag, struct.unpack_from(">H", data, i)[0])
            i += 2
        elif tag in (9, 10, 11, 12):
            pool[n] = (tag, *struct.unpack_from(">HH", data, i))
            i += 4
        elif tag in _FIXED:
            pool[n] = (tag,)
            i += _FIXED[tag]
        else:
            return None, 0
        n += 2 if tag in (5, 6) else 1
    return pool, i


def _utf8(pool, idx) -> str:
    e = pool.get(idx)
    return e[1] if e and e[0] == 1 else ""


def _class_name(pool, idx) -> str:
    e = pool.get(idx)
    return _utf8(pool, e[1]) if e and e[0] == 7 else ""


def _method_ref(pool, idx) -> tuple[str, str, str]:
    e = pool.get(idx)
    if not e or e[0] not in (10, 11):
        return "", "", ""
    nt = pool.get(e[2])
    if not nt or nt[0] != 12:
        return "", "", ""
    return _class_name(pool, e[1]), _utf8(pool, nt[1]), _utf8(pool, nt[2])


def _constant(pool, idx):
    """A string or int constant an `ldc` pushes; None for anything else."""
    e = pool.get(idx)
    if not e:
        return None
    if e[0] == 8:
        return _utf8(pool, e[1])
    if e[0] == 3:
        return e[1]
    return None


def _instructions(code: bytes):
    """(offset, opcode, operand bytes) for each instruction."""
    i = 0
    while i < len(code):
        op = code[i]
        start = i
        i += 1
        if op == 170 or op == 171:                       # tableswitch, lookupswitch
            i += (4 - i % 4) % 4
            if i + 8 > len(code):
                return
            if op == 170:
                low, high = struct.unpack_from(">ii", code, i + 4)
                i += 12 + 4 * max(0, high - low + 1)
            else:
                npairs = struct.unpack_from(">i", code, i + 4)[0]
                i += 8 + 8 * max(0, npairs)
            yield start, op, b""
            continue
        if op == 196:                                    # wide
            if i >= len(code):
                return
            n = 5 if code[i] == 132 else 3
            yield start, op, code[i:i + n]
            i += n
            continue
        n = _OPERANDS.get(op, 0)
        yield start, op, code[i:i + n]
        i += n


def _calls_in(code: bytes, pool, method: str) -> list[Call]:
    calls: list[Call] = []
    run: list = []                # constants pushed with nothing in between
    held: list = []               # the run before an object was built in argument position
    for _, op, arg in _instructions(code):
        const = None
        if 2 <= op <= 8:
            const = op - 3                               # iconst_m1 .. iconst_5
        elif op == 16:
            const = struct.unpack(">b", arg)[0]
        elif op == 17:
            const = struct.unpack(">h", arg)[0]
        elif op == 18:
            const = _constant(pool, arg[0])
        elif op == 19:
            const = _constant(pool, struct.unpack(">H", arg)[0])
        if const is not None:
            run.append(const)
            continue
        if op in (187, 89):                              # new, dup: an argument being constructed
            if op == 187 and run:
                held = run
                run = []
            continue
        if op in _INVOKES:
            owner, name, desc = _method_ref(pool, struct.unpack(">H", arg[:2])[0])
            if owner.startswith(("java/security/", "javax/crypto/")):
                args = run
                if not run and held and name != "<init>":
                    args = held                          # initialize(2048, new SecureRandom())
                calls.append(Call(owner, name, method,
                                  [a for a in args if isinstance(a, str)],
                                  [a for a in args if isinstance(a, int) and not isinstance(a, bool)]))
            if name != "<init>":
                held = []
            run = []
            continue
        run = []
    return calls


def parse(data: bytes) -> ClassInfo | None:
    """JCA calls with constant arguments, per method. None when this is not a class file."""
    pool, i = _constant_pool(data)
    if pool is None:
        return None
    info = ClassInfo()
    try:
        info.name = _class_name(pool, struct.unpack_from(">H", data, i + 2)[0]).replace("/", ".")
        i += 6
        i += 2 + 2 * struct.unpack_from(">H", data, i)[0]                 # interfaces

        def members(i, want_code):
            count = struct.unpack_from(">H", data, i)[0]
            i += 2
            for _ in range(count):
                name = _utf8(pool, struct.unpack_from(">H", data, i + 2)[0])
                attrs = struct.unpack_from(">H", data, i + 6)[0]
                i += 8
                for _ in range(attrs):
                    attr = _utf8(pool, struct.unpack_from(">H", data, i)[0])
                    length = struct.unpack_from(">I", data, i + 2)[0]
                    body = data[i + 6:i + 6 + length]
                    if want_code and attr == "Code" and len(body) >= 8:
                        code_len = struct.unpack_from(">I", body, 4)[0]
                        info.calls.extend(_calls_in(body[8:8 + code_len], pool, name))
                    i += 6 + length
            return i

        i = members(i, False)                                              # fields
        members(i, True)                                                   # methods
    except (struct.error, IndexError):
        pass                                                               # truncated: keep what was read
    return info


# --- JCA names to findings ---------------------------------------------------------------------

@dataclass(frozen=True)
class Use:
    family: str
    role: str
    param: str
    api: str               # how it was asked for, for the evidence line
    method: str


_HASH = {"MD5": "MD5", "MD2": "MD2", "SHA": "SHA-1", "SHA1": "SHA-1", "SHA-1": "SHA-1", "SHA224": "SHA-224", "SHA-224": "SHA-224",
         "SHA256": "SHA-256", "SHA-256": "SHA-256", "SHA384": "SHA-384", "SHA-384": "SHA-384", "SHA512": "SHA-512",
         "SHA-512": "SHA-512", "SHA3-224": "SHA3-224", "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512"}
_CIPHER = {"AES": "AES", "DES": "DES", "DESEDE": "3DES", "TRIPLEDES": "3DES", "3DES": "3DES", "RSA": "RSA", "RC4": "RC4",
           "ARCFOUR": "RC4", "BLOWFISH": "Blowfish", "CHACHA20-POLY1305": "ChaCha20-Poly1305", "CHACHA20": "ChaCha20-Poly1305"}
_KEYPAIR = {"RSA": "RSA", "EC": "ECDSA", "DSA": "DSA", "DH": "DH", "DIFFIEHELLMAN": "DH", "ED25519": "Ed25519", "EDDSA": "Ed25519",
            "X25519": "X25519", "XDH": "X25519", "ECDH": "ECDH", "RSASSA-PSS": "RSA"}
_CURVES = {"SECP256R1": "P-256", "PRIME256V1": "P-256", "NISTP256": "P-256", "P-256": "P-256", "SECP384R1": "P-384",
           "NISTP384": "P-384", "P-384": "P-384", "SECP521R1": "P-521", "NISTP521": "P-521", "P-521": "P-521"}
_MODES = ("ECB", "CBC", "GCM", "CTR", "CFB", "OFB", "CCM")
_PQ = re.compile(r"^(ML-KEM|ML-DSA|SLH-DSA)(?:-([\w-]+))?$", re.I)

STATUS = {
    "RSA": QuantumStatus.VULNERABLE, "ECDSA": QuantumStatus.VULNERABLE, "ECDH": QuantumStatus.VULNERABLE,
    "DSA": QuantumStatus.VULNERABLE, "DH": QuantumStatus.VULNERABLE, "Ed25519": QuantumStatus.VULNERABLE,
    "X25519": QuantumStatus.VULNERABLE, "MD5": QuantumStatus.WEAK, "MD2": QuantumStatus.WEAK, "SHA-1": QuantumStatus.WEAK,
    "DES": QuantumStatus.WEAK, "3DES": QuantumStatus.WEAK, "RC4": QuantumStatus.WEAK, "Blowfish": QuantumStatus.WEAK,
}


def status_of(family: str) -> QuantumStatus:
    if _PQ.match(family):
        return QuantumStatus.PQC
    return STATUS.get(family, QuantumStatus.SAFE_SYMMETRIC)


def _hash(name: str) -> str:
    return _HASH.get(name.upper().replace("_", "-"), "")


def _from_call(c: Call) -> list[Use]:
    """What one `getInstance` or key-spec constructor asks for."""
    simple = c.owner.rsplit("/", 1)[-1]
    if not c.strings or not (c.name == "getInstance" or (simple == "SecretKeySpec" and c.name == "<init>")):
        return []
    # getInstance(algorithm) or getInstance(algorithm, provider); SecretKeySpec(key, algorithm).
    name = c.strings[-1] if simple == "SecretKeySpec" else c.strings[0]
    api = f'{simple}.getInstance("{name}")' if c.name == "getInstance" else f'new SecretKeySpec(..., "{name}")'
    up = name.upper()
    pq = _PQ.match(name)
    if pq:
        fam = pq.group(1).upper() + (f"-{pq.group(2)}" if pq.group(2) else "")
        return [Use(fam, "kem" if "KEM" in fam else "sign", "", api, c.method)]

    def use(family, role, param=""):
        return Use(family, role, param, api, c.method)

    if simple == "MessageDigest":
        return [use(_hash(name), "hash")] if _hash(name) else []
    if simple == "Mac":
        m = re.fullmatch(r"HMAC[-_]?(.+)", up)
        return [use("HMAC", "mac", _hash(m.group(1)))] if m else []
    if simple == "Signature":
        m = re.fullmatch(r"(.+?)WITH(.+?)(?:/PSS|ANDMGF1)?", up)
        if m:
            alg = {"RSA": "RSA", "ECDSA": "ECDSA", "DSA": "DSA", "RSASSA-PSS": "RSA"}.get(m.group(2), "")
            out = [use(alg, "sign")] if alg else []
            if alg and _hash(m.group(1)):
                out.append(use(_hash(m.group(1)), "hash"))           # the hash is in use too
            return out
        fam = _KEYPAIR.get(up)
        return [use(fam, "sign")] if fam else []
    if simple in ("KeyPairGenerator", "KeyFactory", "AlgorithmParameters", "AlgorithmParameterGenerator"):
        fam = _KEYPAIR.get(up)
        return [use(fam, "keygen")] if fam else []
    if simple == "KeyAgreement":
        fam = _KEYPAIR.get(up)
        return [use("ECDH" if fam == "ECDSA" else fam, "kex")] if fam else []
    if simple == "SecretKeyFactory" and up.startswith("PBKDF2"):
        m = re.fullmatch(r"PBKDF2WITHHMAC(.+)", up)
        return [use("PBKDF2", "kdf", _hash(m.group(1)) if m else "")]
    if simple in ("Cipher", "KeyGenerator", "SecretKeyFactory", "SecretKeySpec"):
        parts = up.split("/")
        size = re.fullmatch(r"AES_(128|192|256)", parts[0])
        fam = "AES" if size else _CIPHER.get(parts[0], "")
        if not fam and parts[0].startswith("HMAC"):
            return [use("HMAC", "mac", _hash(parts[0][4:]))]
        if not fam:
            return []
        mode = parts[1] if len(parts) > 1 and parts[1] in _MODES else ""
        bits = size.group(1) if size else ""
        return [use(fam, "cipher", "-".join(x for x in (bits, mode) if x))]
    return []


def _one(values) -> str:
    vals = {v for v in values if v}
    return vals.pop() if len(vals) == 1 else ""


def uses(info: ClassInfo) -> list[Use]:
    """Findings for a class, with key size, curve and mode joined on when the class is unambiguous."""
    found: list[Use] = []
    sizes: dict[str, set[str]] = {}          # generator family -> sizes set on it
    curves: set[str] = set()
    current = {}                             # method -> family of the generator most recently obtained
    for c in info.calls:
        simple = c.owner.rsplit("/", 1)[-1]
        got = _from_call(c)
        found.extend(got)
        if got and simple in ("KeyPairGenerator", "KeyGenerator") and c.name == "getInstance":
            current[c.method] = got[0].family
        elif simple in ("KeyPairGenerator", "KeyGenerator") and c.name in ("initialize", "init") and c.ints:
            fam = current.get(c.method)
            if fam:
                sizes.setdefault(fam, set()).add(str(c.ints[0]))
        elif simple == "ECGenParameterSpec" and c.name == "<init>" and c.strings:
            curves.add(_CURVES.get(c.strings[-1].upper(), c.strings[-1]))
    # A cipher's mode and its key's size are set by different calls. Join them when each is single-valued.
    aes_mode = _one(u.param.split("-")[-1] for u in found if u.family == "AES" and u.param.split("-")[-1] in _MODES)
    out: dict[tuple, Use] = {}
    for u in found:
        param = u.param
        if u.family in ("RSA", "DSA", "DH") and u.role == "keygen":
            param = _one(sizes.get(u.family, ())) or param
        elif u.family in ("ECDSA", "ECDH") and u.role in ("keygen", "kex"):
            param = _one(curves) or param
        elif u.family == "AES":
            bits = _one(sizes.get("AES", ())) or next((p for p in param.split("-") if p.isdigit()), "")
            mode = next((p for p in param.split("-") if p in _MODES), "") or aes_mode
            param = "-".join(x for x in (bits, mode) if x)
        merged = Use(u.family, u.role, param, u.api, u.method)
        key = (u.family, param)
        if key not in out:
            out[key] = merged
    # Drop a bare entry when a fuller one for the same family exists: AES "128-CBC" covers AES "".
    return [u for (fam, param), u in out.items()
            if not any(f == fam and p != param and set(param.split("-")) - {""} < set(p.split("-")) for (f, p) in out)]
