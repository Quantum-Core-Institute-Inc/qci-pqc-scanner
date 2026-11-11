# Artifact score

This number is not the source recall.

An artifact finding comes from a class constant pool, a native library in a JAR, or a file inside an image tarball.

| Field | Meaning |
|-------|---------|
| count | Artifact findings |
| named_class | The snippet names the class |
| with_parameter | Mode, hash, or version is set |

The fixtures in `tests/fixtures/artifacts` are the corpus: `Signer.class`, `app.jar`, `native.jar`, `image.tar`.
