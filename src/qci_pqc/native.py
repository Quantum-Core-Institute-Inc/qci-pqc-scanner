# Copyright (c) 2026 Quantum Core Institute Inc. MIT License.
"""What a native binary asks a crypto library for.

Stripping a binary removes its own function names. It cannot remove the names of the functions it
imports, because the dynamic linker needs them, and it does not remove the strings it passes as
arguments. Those two things are the evidence here. Raw bytes are never pattern-matched: two bytes
that spell "DH" somewhere in a binary mean nothing, and reading them as Diffie-Hellman is how
binaries produced false positives before.

Three kinds of evidence, each tied to something the binary demonstrably does:

1. Imported symbols of a crypto library. `EVP_aes_256_gcm` in the dynamic symbol table is a call
   the program can make, and its name carries key size and mode.
2. Algorithm names passed to fetch-by-name APIs. A NUL-terminated string that is exactly
   `SHA2-512` counts when the binary imports `EVP_MD_fetch`, and only then. Short names such as
   `DH` and `EC` need the specific API that takes them.
3. Go function names. A Go binary keeps the names of the functions linked into it even when
   stripped, and the linker drops unreachable code, so `crypto/rsa.GenerateKey` is there because
   something can call it. When the binary also links `crypto/tls`, the algorithms TLS itself brings
   in are left out: their presence says the program speaks TLS, not what it chose.

Parameters an import cannot name (an RSA key size, a curve, the hash of an HMAC) are read from the
call site on x86-64: the constant loaded into the argument register just before the call, or the
digest getter called just before `HMAC`. They are reported only when every call site agrees and the
value is one that makes sense; otherwise the finding has no parameter.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class Use:
    family: str
    role: str
    param: str
    evidence: str


_CRYPTO_LIBS = re.compile(r"lib(?:crypto|ssl|gcrypt|sodium|mbedcrypto|mbedtls|wolfssl|nettle|hogweed|gnutls|nss3|botan)", re.I)

_DIGESTS = {"md5": "MD5", "md4": "MD4", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
            "sha512": "SHA-512", "sha3_224": "SHA3-224", "sha3_256": "SHA3-256", "sha3_384": "SHA3-384", "sha3_512": "SHA3-512"}
_MODES = {"ecb": "ECB", "cbc": "CBC", "gcm": "GCM", "ctr": "CTR", "ccm": "CCM", "xts": "XTS", "ofb": "OFB", "ocb": "OCB"}


def _mode(token: str) -> str:
    token = token.lower()
    return "CFB" if token.startswith("cfb") else _MODES.get(token, "")


def from_symbol(name: str) -> Use | None:
    """What importing one library function says, if anything."""
    def use(family, role, param=""):
        return Use(family, role, param, f"imports {name}")

    m = re.fullmatch(r"EVP_(md5|md4|sha1|sha224|sha256|sha384|sha512|sha3_(?:224|256|384|512))", name)
    if m:
        return use(_DIGESTS[m.group(1)], "hash")
    m = re.fullmatch(r"(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)(?:_Init|_Update|_Final)?", name)
    if m:
        return use(_DIGESTS[m.group(1).lower()], "hash")
    m = re.fullmatch(r"EVP_aes_(128|192|256)_(\w+)", name)
    if m and _mode(m.group(2)):
        return use("AES", "cipher", f"{m.group(1)}-{_mode(m.group(2))}")
    if re.fullmatch(r"AES_(?:set_(?:en|de)crypt_key|encrypt|decrypt|cbc_encrypt|ecb_encrypt)", name):
        return use("AES", "cipher")
    m = re.fullmatch(r"EVP_des_ede3?(?:_(\w+))?", name)
    if m:
        return use("3DES", "cipher", _mode(m.group(1)) if m.group(1) else "ECB")
    m = re.fullmatch(r"EVP_des_(\w+)", name)
    if m and _mode(m.group(1)):
        return use("DES", "cipher", _mode(m.group(1)))
    if re.fullmatch(r"DES_(?:ecb3_encrypt|ede3_\w+)", name):
        return use("3DES", "cipher")
    if re.fullmatch(r"DES_(?:ecb|cbc|ncbc|cfb|ofb)\w*_encrypt", name):
        return use("DES", "cipher")
    if re.fullmatch(r"EVP_rc4(?:_40|_hmac_md5)?|RC4(?:_set_key)?", name):
        return use("RC4", "cipher")
    if re.fullmatch(r"EVP_chacha20_poly1305|crypto_aead_(?:x)?chacha20poly1305\w*", name):
        return use("ChaCha20-Poly1305", "cipher")
    if re.fullmatch(r"HMAC(?:_Init(?:_ex)?|_CTX_new)?", name):
        return use("HMAC", "mac")
    m = re.fullmatch(r"PKCS5_PBKDF2_HMAC(_SHA1)?", name)
    if m:
        return use("PBKDF2", "kdf", "SHA-1" if m.group(1) else "")
    if re.fullmatch(r"RSA_(?:generate_key(?:_ex)?|new|sign|verify|public_encrypt|private_decrypt|private_encrypt|public_decrypt)"
                    r"|EVP_PKEY_CTX_set_rsa_\w+|PEM_read(?:_bio)?_RSA\w+", name):
        return use("RSA", "keygen" if "gen" in name else "sign")
    if re.fullmatch(r"EC_KEY_(?:new_by_curve_name|generate_key)|EVP_PKEY_CTX_set_ec_paramgen_curve_nid|ECDSA_(?:sign|verify|do_sign|do_verify)\w*", name):
        return use("ECDSA", "keygen" if "ECDSA" not in name else "sign")
    if re.fullmatch(r"ECDH_compute_key", name):
        return use("ECDH", "kex")
    if re.fullmatch(r"DH_(?:generate_parameters(?:_ex)?|generate_key|compute_key|new)|EVP_PKEY_CTX_set_dh_\w+", name):
        return use("DH", "kex")
    if re.fullmatch(r"DSA_(?:generate_parameters(?:_ex)?|generate_key|sign|verify|new)|EVP_PKEY_CTX_set_dsa_\w+", name):
        return use("DSA", "sign")
    if re.fullmatch(r"X25519(?:_keypair|_public_from_private)?|crypto_scalarmult(?:_curve25519)?(?:_base)?|crypto_box_\w+", name):
        return use("X25519", "kex")
    if re.fullmatch(r"ED25519_(?:sign|verify|keypair)|crypto_sign(?:_ed25519)?(?:_keypair|_detached|_verify_detached|_open)?", name):
        return use("Ed25519", "sign")
    return None


# Names OpenSSL's fetch-by-name APIs take. Each kind needs an API that accepts that kind.
_DIGEST_APIS = {"EVP_MD_fetch", "EVP_get_digestbyname", "EVP_Q_digest"}
_CIPHER_APIS = {"EVP_CIPHER_fetch", "EVP_get_cipherbyname"}
_PKEY_APIS = {"EVP_PKEY_CTX_new_from_name", "EVP_PKEY_Q_keygen", "EVP_KEYMGMT_fetch", "EVP_SIGNATURE_fetch", "EVP_KEM_fetch", "EVP_KEYEXCH_fetch"}
_GROUP_APIS = {"OSSL_PARAM_construct_utf8_string", "EVP_PKEY_Q_keygen", "EVP_PKEY_CTX_set_group_name", "OBJ_sn2nid", "OBJ_txt2nid", "EC_curve_nist2nid"}
_DIGEST_NAMES = {"MD5": "MD5", "SHA1": "SHA-1", "SHA-1": "SHA-1", "SHA2-224": "SHA-224", "SHA224": "SHA-224", "SHA-224": "SHA-224",
                 "SHA2-256": "SHA-256", "SHA256": "SHA-256", "SHA-256": "SHA-256", "SHA2-384": "SHA-384", "SHA384": "SHA-384",
                 "SHA-384": "SHA-384", "SHA2-512": "SHA-512", "SHA512": "SHA-512", "SHA-512": "SHA-512",
                 "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512"}
_PKEY_NAMES = {"RSA": ("RSA", "keygen"), "RSA-PSS": ("RSA", "sign"), "EC": ("ECDSA", "keygen"), "DH": ("DH", "kex"), "DHX": ("DH", "kex"),
               "DSA": ("DSA", "sign"), "X25519": ("X25519", "kex"), "ED25519": ("Ed25519", "sign"),
               "ML-KEM-512": ("ML-KEM-512", "kem"), "ML-KEM-768": ("ML-KEM-768", "kem"), "ML-KEM-1024": ("ML-KEM-1024", "kem"),
               "ML-DSA-44": ("ML-DSA-44", "sign"), "ML-DSA-65": ("ML-DSA-65", "sign"), "ML-DSA-87": ("ML-DSA-87", "sign")}
_CURVE_NAMES = {"PRIME256V1": "P-256", "SECP256R1": "P-256", "P-256": "P-256", "SECP384R1": "P-384", "P-384": "P-384",
                "SECP521R1": "P-521", "P-521": "P-521", "SECP256K1": "secp256k1"}
_CURVE_NIDS = {415: "P-256", 715: "P-384", 716: "P-521", 714: "secp256k1"}
_KEY_BITS = {512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 7680, 8192, 15360}
_STRING_RE = re.compile(rb"(?<=\x00)[\x20-\x7e]{2,40}(?=\x00)")


def from_strings(strings: set[str], imports: set[str]) -> list[Use]:
    """Algorithm names the binary can hand to a fetch-by-name API it imports."""
    out: list[Use] = []
    upper = {s.upper(): s for s in strings}
    if imports & _DIGEST_APIS:
        api = sorted(imports & _DIGEST_APIS)[0]
        for up, raw in upper.items():
            if up in _DIGEST_NAMES:
                out.append(Use(_DIGEST_NAMES[up], "hash", "", f'"{raw}" with {api}'))
    if imports & _CIPHER_APIS:
        api = sorted(imports & _CIPHER_APIS)[0]
        for up, raw in upper.items():
            m = re.fullmatch(r"AES-(128|192|256)-(ECB|CBC|GCM|CTR|CCM|XTS|OFB|OCB|CFB\d*)", up)
            if m:
                out.append(Use("AES", "cipher", f"{m.group(1)}-{_mode(m.group(2))}", f'"{raw}" with {api}'))
                continue
            m = re.fullmatch(r"DES-EDE3?(?:-(ECB|CBC|OFB|CFB\d*))?", up)
            if m:
                out.append(Use("3DES", "cipher", _mode(m.group(1)) if m.group(1) else "ECB", f'"{raw}" with {api}'))
                continue
            m = re.fullmatch(r"DES-(ECB|CBC|OFB|CFB\d*)", up)
            if m:
                out.append(Use("DES", "cipher", _mode(m.group(1)), f'"{raw}" with {api}'))
            elif up == "RC4":
                out.append(Use("RC4", "cipher", "", f'"{raw}" with {api}'))
            elif up == "CHACHA20-POLY1305":
                out.append(Use("ChaCha20-Poly1305", "cipher", "", f'"{raw}" with {api}'))
    if imports & _PKEY_APIS:
        api = sorted(imports & _PKEY_APIS)[0]
        groups = {f"ffdhe{n}": str(n) for n in (2048, 3072, 4096, 6144, 8192)}
        groups.update({f"modp_{n}": str(n) for n in (1536, 2048, 3072, 4096, 6144, 8192)})
        dh_bits = {groups[s] for s in strings if s in groups} if imports & _GROUP_APIS else set()
        curves = {_CURVE_NAMES[up] for up in upper if up in _CURVE_NAMES} if imports & _GROUP_APIS else set()
        for up, raw in upper.items():
            if up not in _PKEY_NAMES:
                continue
            fam, role = _PKEY_NAMES[up]
            param = ""
            if fam == "DH" and len(dh_bits) == 1:
                param = next(iter(dh_bits))
            elif fam == "ECDSA" and len(curves) == 1:
                param = next(iter(curves))
            out.append(Use(fam, role, param, f'"{raw}" with {api}'))
    return out


# --- ELF -------------------------------------------------------------------------------------

class Elf:
    def __init__(self, data: bytes):
        self.data = data
        self.ok = data[:4] == b"\x7fELF" and len(data) > 0x40 and data[4] in (1, 2) and data[5] in (1, 2)
        self.sections: list[dict] = []
        self.imports: dict[int, str] = {}        # dynsym index -> name, undefined symbols only
        self.needed: list[str] = []
        if not self.ok:
            return
        self.is64 = data[4] == 2
        self.e = "<" if data[5] == 1 else ">"
        try:
            self.machine = struct.unpack_from(self.e + "H", data, 0x12)[0]
            self._sections()
            self._dynamic()
        except (struct.error, IndexError, ValueError):
            pass

    def _sections(self):
        d, e = self.data, self.e
        if self.is64:
            shoff, = struct.unpack_from(e + "Q", d, 0x28)
            entsize, num, strndx = struct.unpack_from(e + "HHH", d, 0x3A)
        else:
            shoff, = struct.unpack_from(e + "I", d, 0x20)
            entsize, num, strndx = struct.unpack_from(e + "HHH", d, 0x2E)
        if not shoff or not entsize or num > 4096:
            return
        for i in range(num):
            o = shoff + i * entsize
            if self.is64:
                name, typ, flags, addr, off, size, link, info, _, ent = struct.unpack_from(e + "IIQQQQIIQQ", d, o)
            else:
                name, typ, flags, addr, off, size, link, info, _, ent = struct.unpack_from(e + "IIIIIIIIII", d, o)
            self.sections.append({"name": name, "type": typ, "flags": flags, "addr": addr, "off": off, "size": size,
                                  "link": link, "ent": ent})
        if strndx < len(self.sections):
            tab = self.sections[strndx]
            for s in self.sections:
                s["name"] = self._cstr(tab["off"] + s["name"])

    def _cstr(self, off: int) -> str:
        end = self.data.find(b"\x00", off)
        return self.data[off:end].decode("utf-8", "replace") if 0 <= off < end else ""

    def _dynamic(self):
        d, e = self.data, self.e
        for s in self.sections:
            if s["type"] == 11 and s["link"] < len(self.sections):       # SHT_DYNSYM
                strtab = self.sections[s["link"]]
                ent = s["ent"] or (24 if self.is64 else 16)
                for i in range(s["size"] // ent):
                    o = s["off"] + i * ent
                    if self.is64:
                        name, _, _, shndx = struct.unpack_from(e + "IBBH", d, o)
                    else:
                        name, _, _, _, _, shndx = struct.unpack_from(e + "IIIBBH", d, o)
                    if shndx == 0 and name:
                        self.imports[i] = self._cstr(strtab["off"] + name).split("@")[0]
            elif s["type"] == 6 and s["link"] < len(self.sections):      # SHT_DYNAMIC
                strtab = self.sections[s["link"]]
                step = 16 if self.is64 else 8
                for o in range(s["off"], s["off"] + s["size"], step):
                    tag, val = struct.unpack_from(e + ("qQ" if self.is64 else "iI"), d, o)
                    if tag == 0:
                        break
                    if tag == 1:
                        self.needed.append(self._cstr(strtab["off"] + val))

    def strings(self) -> set[str]:
        """NUL-terminated printable strings in the read-only data, whole strings only."""
        out: set[str] = set()
        for s in self.sections:
            if s["name"] in (".rodata", ".rodata.str1.1", ".rodata.str1.8", ".data.rel.ro", ".rdata") or s["name"].startswith(".rodata"):
                blob = b"\x00" + self.data[s["off"]: s["off"] + s["size"]] + b"\x00"
                out.update(m.group(0).decode("ascii") for m in _STRING_RE.finditer(blob))
        return out

    # x86-64 only from here: which library function each call site reaches.
    def calls(self) -> list[tuple[int, str, bytes]]:
        """(address, imported function, the bytes before the call) for each direct call to an import."""
        if not (self.is64 and self.e == "<" and self.machine == 62):
            return []
        d = self.data
        slots: dict[int, str] = {}
        for s in self.sections:
            if s["type"] != 4:                                            # SHT_RELA
                continue
            for o in range(s["off"], s["off"] + s["size"], 24):
                r_off, r_info, _ = struct.unpack_from("<QQq", d, o)
                if (r_info & 0xFFFFFFFF) in (6, 7) and (r_info >> 32) in self.imports:      # GLOB_DAT, JUMP_SLOT
                    slots[r_off] = self.imports[r_info >> 32]
        execs = [s for s in self.sections if s["flags"] & 0x4 and s["type"] == 1]
        stubs: dict[int, str] = {}
        for s in execs:
            blob = d[s["off"]: s["off"] + s["size"]]
            for m in re.finditer(rb"\xff\x25", blob):
                at = s["addr"] + m.start()
                target = at + 6 + struct.unpack_from("<i", blob, m.start() + 2)[0] if m.start() + 6 <= len(blob) else None
                if target in slots:
                    name = slots[target]
                    for back in (0, 1, 4, 5):                             # jmp, bnd jmp, endbr64 + either
                        stubs[at - back] = name
        found = []
        for s in execs:
            blob = d[s["off"]: s["off"] + s["size"]]
            for m in re.finditer(rb"\xe8", blob):
                if m.start() + 5 > len(blob):
                    continue
                at = s["addr"] + m.start()
                target = at + 5 + struct.unpack_from("<i", blob, m.start() + 1)[0]
                if target in stubs:
                    found.append((at, stubs[target], blob[max(0, m.start() - 48): m.start()]))
            for m in re.finditer(rb"\xff\x15", blob):                     # call *slot(%rip), built with -fno-plt
                if m.start() + 6 > len(blob):
                    continue
                at = s["addr"] + m.start()
                target = at + 6 + struct.unpack_from("<i", blob, m.start() + 2)[0]
                if target in slots:
                    found.append((at, slots[target], blob[max(0, m.start() - 48): m.start()]))
        return sorted(found)


def _immediate(before: bytes, opcode: int, allowed) -> int | None:
    """The constant most recently loaded into one argument register before a call (`mov r32, imm32`)."""
    for i in range(len(before) - 5, -1, -1):
        if before[i] == opcode:
            val = struct.unpack_from("<I", before, i + 1)[0]
            if val in allowed:
                return val
    return None


_ESI, _EDI, _ECX = 0xBE, 0xBF, 0xB9


def _call_site_params(elf: Elf) -> dict[str, str]:
    """family -> parameter, where every call site that sets it agrees."""
    calls = elf.calls()
    seen: dict[str, set[str]] = {}
    last_digest: tuple[int, str] | None = None
    for at, name, before in calls:
        m = re.fullmatch(r"EVP_(md5|md4|sha1|sha224|sha256|sha384|sha512|sha3_(?:224|256|384|512))", name)
        if m:
            last_digest = (at, _DIGESTS[m.group(1)])
            continue
        if name in ("EVP_PKEY_CTX_set_rsa_keygen_bits", "RSA_generate_key_ex", "RSA_generate_key"):
            v = _immediate(before, _EDI if name == "RSA_generate_key" else _ESI, _KEY_BITS)
            seen.setdefault("RSA", set()).add(str(v) if v else "")
        elif name in ("EVP_PKEY_CTX_set_dh_paramgen_prime_len", "DH_generate_parameters_ex"):
            v = _immediate(before, _ESI, _KEY_BITS)
            seen.setdefault("DH", set()).add(str(v) if v else "")
        elif name in ("EVP_PKEY_CTX_set_dsa_paramgen_bits", "DSA_generate_parameters_ex"):
            v = _immediate(before, _ESI, _KEY_BITS)
            seen.setdefault("DSA", set()).add(str(v) if v else "")
        elif name in ("EVP_PKEY_CTX_set_ec_paramgen_curve_nid", "EC_KEY_new_by_curve_name"):
            v = _immediate(before, _EDI if name == "EC_KEY_new_by_curve_name" else _ESI, _CURVE_NIDS)
            seen.setdefault("ECDSA", set()).add(_CURVE_NIDS.get(v, ""))
        elif name in ("HMAC", "HMAC_Init_ex", "PKCS5_PBKDF2_HMAC"):
            fam = "PBKDF2" if name.startswith("PKCS5") else "HMAC"
            near = last_digest[1] if last_digest and 0 < at - last_digest[0] <= 96 else ""
            seen.setdefault(fam, set()).add(near)
    return {fam: next(iter(vals)) for fam, vals in seen.items() if len(vals) == 1 and "" not in vals}


# --- Go --------------------------------------------------------------------------------------

_GO_NAME_RE = re.compile(rb"(?<=\x00)(?:crypto|golang\.org/x/crypto)/[a-z0-9/]+\.[A-Za-z(][\w.*()]{0,60}(?=\x00)")
# package.Function -> (family, role, param). Public entry points only: internal helpers are linked
# for many reasons, an entry point because something calls it.
_GO_ENTRY = {
    "crypto/md5.New": ("MD5", "hash", ""), "crypto/md5.Sum": ("MD5", "hash", ""),
    "crypto/sha1.New": ("SHA-1", "hash", ""), "crypto/sha1.Sum": ("SHA-1", "hash", ""),
    "crypto/sha256.New": ("SHA-256", "hash", ""), "crypto/sha256.Sum256": ("SHA-256", "hash", ""),
    "crypto/sha512.New": ("SHA-512", "hash", ""), "crypto/sha512.Sum512": ("SHA-512", "hash", ""),
    "crypto/sha512.New384": ("SHA-384", "hash", ""), "crypto/sha512.Sum384": ("SHA-384", "hash", ""),
    "crypto/sha3.New256": ("SHA3-256", "hash", ""), "crypto/sha3.Sum256": ("SHA3-256", "hash", ""),
    "golang.org/x/crypto/sha3.New256": ("SHA3-256", "hash", ""), "golang.org/x/crypto/sha3.Sum256": ("SHA3-256", "hash", ""),
    "crypto/hmac.New": ("HMAC", "mac", ""),
    "crypto/aes.NewCipher": ("AES", "cipher", ""),
    "crypto/des.NewCipher": ("DES", "cipher", ""), "crypto/des.NewTripleDESCipher": ("3DES", "cipher", ""),
    "crypto/rc4.NewCipher": ("RC4", "cipher", ""),
    "crypto/rsa.GenerateKey": ("RSA", "keygen", ""), "crypto/rsa.GenerateMultiPrimeKey": ("RSA", "keygen", ""),
    "crypto/rsa.SignPKCS1v15": ("RSA", "sign", ""), "crypto/rsa.SignPSS": ("RSA", "sign", ""),
    "crypto/rsa.EncryptOAEP": ("RSA", "encrypt", ""), "crypto/rsa.EncryptPKCS1v15": ("RSA", "encrypt", ""),
    "crypto/rsa.DecryptOAEP": ("RSA", "encrypt", ""), "crypto/rsa.DecryptPKCS1v15": ("RSA", "encrypt", ""),
    "crypto/ecdsa.GenerateKey": ("ECDSA", "keygen", ""), "crypto/ecdsa.Sign": ("ECDSA", "sign", ""),
    "crypto/ecdsa.SignASN1": ("ECDSA", "sign", ""),
    "crypto/ed25519.GenerateKey": ("Ed25519", "sign", ""), "crypto/ed25519.Sign": ("Ed25519", "sign", ""),
    "crypto/dsa.GenerateKey": ("DSA", "sign", ""), "crypto/dsa.GenerateParameters": ("DSA", "sign", ""), "crypto/dsa.Sign": ("DSA", "sign", ""),
    "crypto/ecdh.X25519": ("X25519", "kex", ""), "golang.org/x/crypto/curve25519.X25519": ("X25519", "kex", ""),
    "crypto/mlkem.GenerateKey768": ("ML-KEM-768", "kem", ""), "crypto/mlkem.NewDecapsulationKey768": ("ML-KEM-768", "kem", ""),
    "crypto/mlkem.GenerateKey1024": ("ML-KEM-1024", "kem", ""), "crypto/mlkem.NewDecapsulationKey1024": ("ML-KEM-1024", "kem", ""),
    "golang.org/x/crypto/chacha20poly1305.New": ("ChaCha20-Poly1305", "cipher", ""),
    "golang.org/x/crypto/pbkdf2.Key": ("PBKDF2", "kdf", ""), "crypto/pbkdf2.Key": ("PBKDF2", "kdf", ""),
}
_GO_MODES = {"crypto/cipher.NewGCM": "GCM", "crypto/cipher.NewGCMWithNonceSize": "GCM", "crypto/cipher.NewCBCEncrypter": "CBC",
             "crypto/cipher.NewCBCDecrypter": "CBC", "crypto/cipher.NewCTR": "CTR", "crypto/cipher.NewCFBEncrypter": "CFB",
             "crypto/cipher.NewOFB": "OFB"}
# What the TLS stack reaches on its own. With crypto/tls linked these say nothing about the program.
_GO_TLS_OWN = {"crypto/md5.New", "crypto/sha1.New", "crypto/sha256.New", "crypto/sha512.New", "crypto/sha512.New384",
               "crypto/sha256.Sum256", "crypto/sha512.Sum512", "crypto/sha512.Sum384", "crypto/sha1.Sum", "crypto/md5.Sum",
               "crypto/hmac.New", "crypto/aes.NewCipher", "crypto/des.NewCipher", "crypto/des.NewTripleDESCipher",
               "crypto/rc4.NewCipher", "crypto/rsa.SignPKCS1v15", "crypto/rsa.SignPSS", "crypto/rsa.EncryptPKCS1v15",
               "crypto/rsa.DecryptPKCS1v15", "crypto/rsa.DecryptOAEP", "crypto/ecdsa.Sign", "crypto/ecdsa.SignASN1",
               "crypto/ed25519.Sign", "crypto/ecdh.X25519", "golang.org/x/crypto/chacha20poly1305.New",
               "crypto/mlkem.GenerateKey768", "crypto/mlkem.NewDecapsulationKey768", "crypto/mlkem.GenerateKey1024",
               "crypto/mlkem.NewDecapsulationKey1024", "golang.org/x/crypto/curve25519.X25519",
               "crypto/dsa.Sign", "crypto/sha3.New256", "crypto/sha3.Sum256"}


def go_functions(data: bytes) -> set[str]:
    if b"\xff Go buildinf:" not in data:
        return set()
    return {m.group(0).decode("ascii") for m in _GO_NAME_RE.finditer(data)}


# A hash package registers its constructor at start-up, so `New` is linked whenever anything
# imports the package. These standard-library packages import these hash packages for their own
# use; when one of them is linked, the hash package's presence is explained without the program.
_GO_PULLS = {"crypto/rsa": {"crypto/sha3"}, "crypto/ecdsa": {"crypto/sha512", "crypto/sha3"}, "crypto/ed25519": {"crypto/sha512"},
             "crypto/mlkem": {"crypto/sha3"}, "crypto/x509": {"crypto/md5", "crypto/sha1", "crypto/sha256", "crypto/sha512"}}
_GO_REGISTERED = re.compile(r"crypto/(?:md5|sha1|sha256|sha512|sha3)\.New\w*")


def from_go(functions: set[str]) -> list[Use]:
    tls = any(f.startswith("crypto/tls.") for f in functions)
    modes = {_GO_MODES[f] for f in functions if f in _GO_MODES}
    packages = {f.rsplit(".", 1)[0] for f in functions}
    explained = set().union(*(pulled for pkg, pulled in _GO_PULLS.items() if pkg in packages))
    out = []
    for fn in sorted(functions):
        if fn not in _GO_ENTRY or (tls and fn in _GO_TLS_OWN):
            continue
        if _GO_REGISTERED.fullmatch(fn) and fn.rsplit(".", 1)[0] in explained:
            continue
        fam, role, param = _GO_ENTRY[fn]
        if fam == "AES" and len(modes) == 1 and not tls:
            param = next(iter(modes))
        out.append(Use(fam, role, param, f"links {fn}"))
    return out


# --- entry point -----------------------------------------------------------------------------

def analyze(data: bytes) -> list[Use]:
    """Findings for one native binary. Empty for anything that is not an ELF file."""
    elf = Elf(data)
    if not elf.ok:
        return []
    uses: list[Use] = []
    imports = set(elf.imports.values())
    if imports and any(_CRYPTO_LIBS.search(lib) for lib in elf.needed):
        lib = next(lib for lib in elf.needed if _CRYPTO_LIBS.search(lib))
        for name in sorted(imports):
            u = from_symbol(name)
            if u:
                uses.append(Use(u.family, u.role, u.param, f"{u.evidence} from {lib}"))
        uses.extend(from_strings(elf.strings(), imports))
        site = _call_site_params(elf)
        uses = [Use(u.family, u.role, u.param or site.get(u.family, ""), u.evidence) for u in uses]
    uses.extend(from_go(go_functions(data)))
    # One finding per family and parameter; a bare entry gives way to one that says more.
    best: dict[tuple[str, str], Use] = {}
    for u in uses:
        best.setdefault((u.family, u.param), u)
    return [u for (fam, param), u in best.items() if param or not any(f == fam and p for (f, p) in best)]
