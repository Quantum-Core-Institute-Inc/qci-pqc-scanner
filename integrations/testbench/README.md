# Testbench adapter

Copy `qci_pqc.py` to `tools/adapters/qci_pqc.py` in the CBOM testbench.

It maps `HMAC-SHA-256`, `HMAC-SHA-1`, `HMAC-SHA-512`, `PBKDF2-SHA-256`, and `PBKDF2-SHA-1` through, so the hash in the component name is scored instead of dropped.
