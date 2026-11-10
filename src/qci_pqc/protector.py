"""Record where a key is protected. Do not talk to the HSM or KMS."""

from __future__ import annotations

import re


def protector(text: str) -> str:
    if re.search(r"kms|aws_kms|vault", text, re.I):
        return "kms"
    if re.search(r"hsm|pkcs11", text, re.I):
        return "hsm"
    if re.search(r"BEGIN (RSA |EC )?PRIVATE KEY", text):
        return "file"
    return ""


def state(text: str) -> str:
    if re.search(r"compromised|revoked", text, re.I):
        return "compromised"
    if re.search(r"BEGIN", text):
        return "active"
    return ""
