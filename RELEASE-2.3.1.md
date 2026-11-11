# QCI Crypto Inventory 2.3.1

Fixes from the v2.3.0 review. Source scanning is unchanged.

## Fixes

- A policy violation exits 1. A waived finding does not.
- A waiver names the path. Two call sites in one JAR stay two.
- An empty inventory is not scored. PQC does not offset a vulnerable finding.
- SHA-256 is not vulnerable. SHA-512 does not get a PQC level.
- The report is escaped. A symlink that leaves the tree is skipped. Archives are bounded.

## Added

- A coverage record. A partial scan is visible.
- Recall by surface. The corpus is named as bundled.
- The evidence manifest names the build, the revision, and the policy.
- A ticket carries the owner, the system, and the data lifetime.
- `--supplier-cbom` reconciles a scan with a supplier CBOM.
