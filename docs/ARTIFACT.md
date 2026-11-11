# Artifact score

This number is not the source recall.

An artifact finding comes from a class constant pool, a native library in a JAR, or a file inside an image tarball.

| Field | Meaning |
|-------|---------|
| count | Artifact findings |
| named_class | The snippet names the class |
| with_parameter | Mode, hash, or version is set |

The fixtures in `tests/fixtures/artifacts` are the corpus: `Signer.class`, `app.jar`, `native.jar`, `image.tar`.


## Published corpus

`tests/fixtures/artifacts/expected.json` is the artifact corpus. Six expected findings: RSA and HMAC from `Signer.sign`, OpenSSL from a JAR and from disk, a native that must not be called OpenSSL, and a config from an image tarball.

This number is not the source recall.
