"""Native binaries: what a binary imports, the names it hands to fetch APIs, and Go functions it links."""
import struct

from qci_pqc import native
from qci_pqc.artifacts import scan_artifacts


def elf(imports, needed=("libcrypto.so.3",), rodata=b"", text=b"", extra=b""):
    """A minimal x86-64 ELF: dynamic symbols, DT_NEEDED, .rodata, one PLT stub per import, and .text.
    `text` may contain b"<CALL:name>" markers, replaced by a call to that import's stub."""
    dynstr = b"\x00"
    def s(name):
        nonlocal dynstr
        off = len(dynstr)
        dynstr += name.encode() + b"\x00"
        return off
    sym_names = [s(n) for n in imports]
    need = [s(n) for n in needed]
    dynsym = b"\x00" * 24 + b"".join(struct.pack("<IBBHQQ", n, 0x12, 0, 0, 0, 0) for n in sym_names)
    dynamic = b"".join(struct.pack("<qQ", 1, n) for n in need) + struct.pack("<qQ", 0, 0)
    got, plt_addr, text_addr = 0x4000, 0x1000, 0x2000
    rela = b"".join(struct.pack("<QQq", got + 8 * i, ((i + 1) << 32) | 7, 0) for i in range(len(imports)))
    plt = b"".join(b"\xff\x25" + struct.pack("<i", got + 8 * i - (plt_addr + 16 * i + 6)) + b"\x90" * 10 for i in range(len(imports)))
    head, *calls = text.split(b"<CALL:")
    code = head
    for part in calls:
        name, _, rest = part.partition(b">")
        at = text_addr + len(code)
        code += b"\xe8" + struct.pack("<i", plt_addr + 16 * imports.index(name.decode()) - (at + 5)) + rest
    names = [b"", b".dynstr", b".dynsym", b".dynamic", b".rodata", b".rela.plt", b".plt", b".text", b".shstrtab"]
    shstr, name_off = b"", []
    for n in names:
        name_off.append(len(shstr))
        shstr += n + b"\x00"
    bodies = [b"", dynstr, dynsym, dynamic, rodata, rela, plt, code, shstr]
    types = [0, 3, 11, 6, 1, 4, 1, 1, 3]
    flags = [0, 2, 2, 3, 2, 2, 6, 6, 0]
    addrs = [0, 0, 0, 0, 0x3000, 0, plt_addr, text_addr, 0]
    links = [0, 0, 1, 1, 0, 2, 0, 0, 0]
    ents = [0, 0, 24, 16, 0, 24, 0, 0, 0]
    out = bytearray(64)
    offs = []
    for b in bodies:
        offs.append(len(out))
        out += b
    out += extra
    shoff = len(out)
    for i in range(len(names)):
        out += struct.pack("<IIQQQQIIQQ", name_off[i], types[i], flags[i], addrs[i], offs[i], len(bodies[i]), links[i], 0, 1, ents[i])
    out[:20] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 3, 62)
    struct.pack_into("<Q", out, 0x28, shoff)
    struct.pack_into("<HHH", out, 0x3A, 64, len(names), len(names) - 1)
    return bytes(out)


def found(data):
    return {(u.family, u.param) for u in native.analyze(data)}


def test_imports_from_a_crypto_library():
    data = elf(["EVP_md5", "EVP_aes_256_gcm", "EVP_des_ede3_cbc", "EVP_EncryptInit_ex", "printf"])
    assert found(data) == {("MD5", ""), ("AES", "256-GCM"), ("3DES", "CBC")}


def test_the_same_names_without_a_crypto_library_are_nothing():
    """A program that defines or imports its own EVP_md5 from somewhere else is not using OpenSSL."""
    assert found(elf(["EVP_md5", "EVP_aes_256_gcm"], needed=("libc.so.6",))) == set()


def test_bytes_that_spell_an_algorithm_are_not_evidence():
    """DH, RSA and MD5 as strings in the data, with no API that takes a name: nothing."""
    data = elf(["EVP_EncryptInit_ex"], rodata=b"\x00DH\x00RSA\x00MD5\x00AES-128-ECB\x00", extra=b"xxDHxxRSAxxMD5xx")
    assert found(data) == set()


def test_names_handed_to_fetch_apis():
    data = elf(["EVP_MD_fetch", "EVP_CIPHER_fetch", "EVP_PKEY_CTX_new_from_name", "OSSL_PARAM_construct_utf8_string"],
               rodata=b"\x00SHA2-512\x00AES-128-ECB\x00DH\x00ffdhe2048\x00usage: fwcheck\x00")
    assert found(data) == {("SHA-512", ""), ("AES", "128-ECB"), ("DH", "2048")}


def test_a_short_name_needs_the_api_that_takes_it():
    """"DH" in the data counts for EVP_PKEY_CTX_new_from_name, not for EVP_MD_fetch."""
    assert found(elf(["EVP_MD_fetch"], rodata=b"\x00DH\x00EC\x00")) == set()


def test_key_size_and_hmac_hash_from_the_call_site():
    text = (b"\xbe\x00\x08\x00\x00" b"<CALL:EVP_PKEY_CTX_set_rsa_keygen_bits>"        # mov esi, 2048
            b"\x90\x90" b"<CALL:EVP_sha256>" b"\x48\x89\xc7" b"<CALL:HMAC>" b"\xc3")
    data = elf(["EVP_PKEY_CTX_set_rsa_keygen_bits", "EVP_sha256", "HMAC"], text=text)
    assert found(data) == {("RSA", "2048"), ("SHA-256", ""), ("HMAC", "SHA-256")}


def test_two_key_sizes_mean_no_key_size():
    text = (b"\xbe\x00\x08\x00\x00" b"<CALL:EVP_PKEY_CTX_set_rsa_keygen_bits>"
            b"\xbe\x00\x10\x00\x00" b"<CALL:EVP_PKEY_CTX_set_rsa_keygen_bits>" b"\xc3")
    assert found(elf(["EVP_PKEY_CTX_set_rsa_keygen_bits"], text=text)) == {("RSA", "")}


GO = b"\xff Go buildinf:\x00"


def go_binary(*functions):
    return elf([], needed=(), extra=GO + b"\x00" + b"\x00".join(f.encode() for f in functions) + b"\x00")


def test_go_functions_linked_into_a_stripped_binary():
    data = go_binary("crypto/rsa.GenerateKey", "crypto/sha256.Sum256", "crypto/hmac.New", "crypto/sha1.New",
                     "crypto/internal/fips140/sha512.New", "main.main")
    assert found(data) == {("RSA", ""), ("SHA-256", ""), ("HMAC", ""), ("SHA-1", "")}


def test_go_hash_packages_the_standard_library_links_by_itself():
    """crypto/rsa imports crypto/sha3, so sha3.New256 is there in every program that uses RSA."""
    assert found(go_binary("crypto/rsa.GenerateKey", "crypto/sha3.New256")) == {("RSA", "")}
    assert found(go_binary("crypto/sha3.New256")) == {("SHA3-256", "")}


def test_go_with_tls_does_not_report_what_tls_brings():
    data = go_binary("crypto/tls.(*Conn).Handshake", "crypto/sha1.New", "crypto/aes.NewCipher", "crypto/des.NewTripleDESCipher",
                     "crypto/mlkem.GenerateKey1024", "crypto/rsa.GenerateKey")
    assert found(data) == {("RSA", "")}


def test_not_elf():
    assert native.analyze(b"MZ\x90\x00 not elf") == []
    assert native.analyze(b"\x7fELF\x02\x01\x01" + b"\x00" * 20) == []


def test_end_to_end_binary_is_read_and_not_listed_as_skipped(tmp_path):
    (tmp_path / "meterd").write_bytes(elf(["EVP_md5", "EVP_des_ede3_cbc"]))
    out = {(f.family, f.parameter_set) for f in scan_artifacts(tmp_path)}
    assert ("MD5", "") in out and ("3DES", "CBC") in out
    from qci_pqc import coverage
    from qci_pqc.scanner import scan_path
    list(scan_path(tmp_path))
    assert not [s for s in coverage.summary().get("skipped", []) if "meterd" in str(s)]
