# QCI Crypto Inventory 2.3.2

Three acceptance tests from the 2.3.1 review. No new detection.

- An out-of-tree artifact is not read. A symlink the source pass skipped is skipped by the artifact pass too.
- A partial scan fails the gate. A skipped archive or a failed adapter exits 1.
- The evidence manifest hashes the final files. It is written after the policy result, the tickets, and the reconciliation.
