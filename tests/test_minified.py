"""Minified JavaScript: the calls are intact, only the names are shortened."""
from qci_pqc import minified
from qci_pqc.dedupe import deduplicate
from qci_pqc.scanner import scan_path

BUNDLE = (
    '"use strict";const e=require("node:crypto"),n="sha1",t="aes-256-gcm";'
    'function a(t,r){return e.createHash(n).update(t+r).digest("hex")}'
    'function o(n,r){const c=e.randomBytes(12),i=e.createCipheriv(t,n,c);return i.update(r)}'
    'function u(){return e.generateKeyPairSync("rsa",{modulusLength:1024})}'
    "module.exports={a:a,o:o,u:u};"
)


def expanded(text):
    return "\n".join(minified.expand(text)[0])


def test_module_alias_and_hoisted_strings_are_put_back():
    out = expanded(BUNDLE)
    assert 'crypto.createHash("sha1")' in out
    assert 'crypto.createCipheriv("aes-256-gcm",n,c)' in out
    assert 'crypto.generateKeyPairSync("rsa",{modulusLength:1024})' in out


def test_a_letter_reused_inside_a_function_is_left_alone():
    """`t` is "aes-256-gcm" at the top and a parameter in a(); `n` is "sha1" at the top and a parameter in o()."""
    out = expanded(BUNDLE)
    assert "update(t+r)" in out                       # a()'s own t, not the cipher name
    assert '("aes-256-gcm","sha1",c)' not in out      # o()'s own n, not the hash name


def test_destructured_require_and_named_imports():
    cjs = 'const{createHmac:e,pbkdf2Sync:r}=require("crypto");function a(t,n){return e("sha512",t).update(n).digest()}function o(e,t){return r(e,t,1e5,32,"sha256")}'
    out = expanded(cjs)
    assert 'crypto.createHmac("sha512",t)' in out
    assert 'crypto.pbkdf2Sync(e,t,1e5,32,"sha256")' in out          # e is o()'s parameter there
    esm = 'import{createHash as e}from"node:crypto";export function a(t){return e("md5").update(t).digest("hex")}'
    assert 'crypto.createHash("md5")' in expanded(esm)


def test_a_name_assigned_twice_is_not_a_constant():
    text = 'const e=require("crypto");let n="sha1";n="sha256";function a(t){return e.createHash(n).update(t)}' + ";" * 30
    assert "crypto.createHash(n)" in expanded(text)


def test_object_keys_and_properties_are_not_names():
    text = 'const e=require("crypto"),n="sha1";function a(t){return{n:1,v:t.n,h:e.createHash(n)}}'
    out = expanded(text)
    assert "{n:1,v:t.n,h:crypto.createHash(\"sha1\")}" in out


def test_only_minified_files_are_expanded():
    assert minified.is_minified("app.min.js", "x")
    assert minified.is_minified("bundle.js", "a=1;" * 400)
    assert not minified.is_minified("server.js", "const crypto = require('crypto');\nconst h = crypto.createHash('sha256');\n")


def test_findings_keep_the_line_of_the_file(tmp_path):
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "app.min.js").write_text("/* build 41 */\n" + BUNDLE)
    found = {(f.family, f.parameter_set, f.evidence_line) for f in deduplicate(list(scan_path(tmp_path)))}
    assert ("SHA-1", "SHA-1", 2) in found
    assert ("AES", "256-GCM", 2) in found
    assert ("RSA", "1024", 2) in found


def test_build_output_is_read_for_bundles_only(tmp_path):
    """dist/ holds what ships. A minified bundle there is read; a plain source copy stays skipped."""
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "app.min.js").write_text(BUNDLE)
    (tmp_path / "dist" / "copy.js").write_text("const crypto = require('crypto');\nconst h = crypto.createHash('md5');\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.min.js").write_text(BUNDLE)
    paths = {f.evidence_path for f in scan_path(tmp_path)}
    assert "dist/app.min.js" in paths
    assert "dist/copy.js" not in paths
    assert not any(p.startswith("node_modules") for p in paths)
