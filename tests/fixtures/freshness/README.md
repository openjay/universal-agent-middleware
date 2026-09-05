# Freshness Test Protocol (E2E-FRESH-001)

This mini-repo exists solely to prove ChatGPT reads **live** data through UAM,
not a cached snapshot.

## Protocol

### T0 — Baseline read

1. In a ChatGPT session with UAM app enabled, ask:
   > "Using UAM, read the file test.txt from the freshness workspace and tell me the current HEAD commit."

2. Expected response:
   - `HEAD` = the commit hash from `freshness baseline T0`
   - `test.txt` content = `v1`

### T1 — Mutate locally (do NOT restart tunnel or rescan)

```bash
cd tests/fixtures/freshness
echo "v2" > test.txt
git add test.txt
git commit -m "freshness test T1"
```

### T2 — Re-read in SAME ChatGPT conversation

Ask in the same conversation:
> "Read test.txt from freshness workspace again and tell me the new HEAD."

Expected:
- `HEAD` = new commit hash (different from T0)
- `test.txt` content = `v2`

## PASS criteria

- HEAD changed without any tunnel restart
- File content changed without any tunnel restart
- No "Scan Tools" re-invocation needed
- No app recreation needed

This proves the tunnel provides live pass-through, not a snapshot cache.
