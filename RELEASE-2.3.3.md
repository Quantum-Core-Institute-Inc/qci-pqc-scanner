# QCI Crypto Inventory 2.3.3

The open cases from the 2.3.2 review. No new detection.

- A linked image tar outside the tree is not read.
- A corrupt archive and a JAR over 2,000 files are recorded as skipped. The gate fails.
- The manifest hashes only the files this run wrote. A run without a policy does not keep the old policy file.
- Policy and dependency rows are escaped.
- The scheduled scan computes the readiness score and attaches coverage.
