# Releasing

## Version bump
1. Update `version` in `pyproject.toml`
2. Update `__version__` in `src/qci_pqc/__init__.py`
3. Commit

## Tag and release
```bash
git tag -a v0.3.0 -m "Release v0.3.0"
git push origin v0.3.0
```

The release workflow:
- Builds the package
- Generates SHA256SUMS
- Attaches `docs/LIMITATIONS.md` prominently
- Creates a GitHub Release

## Limitations
Every release includes `LIMITATIONS.md`. Operators should read it before relying on scan outcomes.
