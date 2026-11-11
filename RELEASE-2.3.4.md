# QCI Crypto Inventory 2.3.4

The two blockers from the 2.3.3.1 review.

- A corrupt JAR inside a valid WAR is recorded as skipped. The gate fails.
- The source pass checks a symlink before it reads. An out-of-tree file is not opened.
