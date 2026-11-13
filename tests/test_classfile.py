"""Compiled Java: a constant handed to a JCA call, read from the bytecode."""
import struct
import zipfile

from qci_pqc import classfile
from qci_pqc.artifacts import scan_artifacts


class Assembler:
    """Just enough of the class file format to write one class with static methods."""

    def __init__(self, name="Demo"):
        self.pool, self.index, self.methods = [], {}, []
        self.this = self.klass(name)
        self.super_ = self.klass("java/lang/Object")

    def _add(self, key, raw):
        if key not in self.index:
            self.pool.append(raw)
            self.index[key] = len(self.pool)
        return self.index[key]

    def utf8(self, s):
        b = s.encode()
        return self._add(("u", s), b"\x01" + struct.pack(">H", len(b)) + b)

    def klass(self, s):
        return self._add(("c", s), b"\x07" + struct.pack(">H", self.utf8(s)))

    def string(self, s):
        return self._add(("s", s), b"\x08" + struct.pack(">H", self.utf8(s)))

    def method_ref(self, owner, name, desc):
        nt = self._add(("nt", name, desc), b"\x0c" + struct.pack(">HH", self.utf8(name), self.utf8(desc)))
        return self._add(("m", owner, name, desc), b"\x0a" + struct.pack(">HH", self.klass(owner), nt))

    def ldc(self, s):
        return bytes([18, self.string(s)])

    def invokestatic(self, owner, name, desc):
        return bytes([184]) + struct.pack(">H", self.method_ref(owner, name, desc))

    def invokevirtual(self, owner, name, desc):
        return bytes([182]) + struct.pack(">H", self.method_ref(owner, name, desc))

    def method(self, name, code):
        self.methods.append((self.utf8(name), self.utf8("()V"), self.utf8("Code"), code + b"\xb1"))

    def build(self):
        out = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, len(self.pool) + 1) + b"".join(self.pool)
        out += struct.pack(">HHHHH", 0x21, self.this, self.super_, 0, 0) + struct.pack(">H", len(self.methods))
        for name, desc, code_attr, code in self.methods:
            body = struct.pack(">HHI", 4, 4, len(code)) + code + struct.pack(">HH", 0, 0)
            out += struct.pack(">HHHH", 0x9, name, desc, 1) + struct.pack(">HI", code_attr, len(body)) + body
        return out + struct.pack(">H", 0)


GET = "(Ljava/lang/String;)Ljava/security/MessageDigest;"


def uses(asm):
    return {(u.family, u.param) for u in classfile.uses(classfile.parse(asm.build()))}


def test_a_constant_handed_to_a_jca_call_is_a_finding():
    a = Assembler()
    a.method("digest", a.ldc("SHA-1") + a.invokestatic("java/security/MessageDigest", "getInstance", GET) + b"\x57")
    a.method("seal", a.ldc("DES/ECB/PKCS5Padding")
             + a.invokestatic("javax/crypto/Cipher", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;") + b"\x57")
    assert uses(a) == {("SHA-1", ""), ("DES", "ECB")}


def test_key_size_and_signature_hash():
    a = Assembler()
    kpg = "java/security/KeyPairGenerator"
    a.method("keys", a.ldc("RSA") + a.invokestatic(kpg, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyPairGenerator;")
             + b"\x4b\x2a" + b"\x11" + struct.pack(">h", 1024) + a.invokevirtual(kpg, "initialize", "(I)V")     # astore_0, aload_0, sipush
             + a.ldc("SHA256withRSA")
             + a.invokestatic("java/security/Signature", "getInstance", "(Ljava/lang/String;)Ljava/security/Signature;") + b"\x57")
    assert uses(a) == {("RSA", "1024"), ("SHA-256", "")}


def test_a_string_that_only_looks_like_an_algorithm_is_not_a_finding():
    """ "EC" printed, and "MD5" sitting in the constant pool with no JCA call at all."""
    a = Assembler()
    a.string("MD5")
    a.method("label", a.ldc("EC") + a.invokestatic("java/lang/String", "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;") + b"\x57")
    assert uses(a) == set()


def test_a_name_that_is_not_a_constant_is_not_guessed():
    """getInstance(arg): something else was pushed between the last constant and the call."""
    a = Assembler()
    a.method("digest", a.ldc("MD5") + b"\x57" + b"\x2a"                     # pop, aload_0
             + a.invokestatic("java/security/MessageDigest", "getInstance", GET) + b"\x57")
    assert uses(a) == set()


def test_not_a_class_file():
    assert classfile.parse(b"PK\x03\x04 not a class") is None
    assert classfile.parse(b"\xca\xfe\xba\xbe\x00\x00\x00\x34\xff\xff") is None      # truncated pool


def test_end_to_end_jar(tmp_path):
    a = Assembler("a")                                                       # an obfuscated name changes nothing
    a.method("b", a.ldc("SHA-1") + a.invokestatic("java/security/MessageDigest", "getInstance", GET) + b"\x57")
    with zipfile.ZipFile(tmp_path / "vault.jar", "w") as z:
        z.writestr("a.class", a.build())
    found = [(f.family, f.evidence_path, f.evidence_snippet) for f in scan_artifacts(tmp_path) if f.family == "SHA-1"]
    assert len(found) == 1
    assert 'MessageDigest.getInstance("SHA-1")' in found[0][2] and "a.b" in found[0][2]
