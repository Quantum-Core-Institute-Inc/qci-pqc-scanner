# Safe-only file — should not produce vulnerable findings
import hashlib
h = hashlib.sha256(b"only-safe")
