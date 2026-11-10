# Testbench adapter

`qci_pqc.py` is the adapter the CBOM testbench uses to credit names.

After any change here, copy it into the testbench before scoring:

```bash
cp integrations/testbench/qci_pqc.py /path/to/cbom-testbench/tools/adapters/qci_pqc.py
```

A detection that is not in this map is dropped, even if the scanner found it.
