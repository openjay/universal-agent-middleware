## Summary

<!-- Describe the change and why it is needed. -->

## Type

- [ ] Bug fix
- [ ] Feature (Preview contract impact — link issue/RFC)
- [ ] Documentation
- [ ] Test / CI
- [ ] Security fix (do not describe exploit details publicly)

## Preview Contract Check

- [ ] Session-read MCP profile remains read-only (no new write/exec tools)
- [ ] No machine-specific paths or credentials in changes
- [ ] Tests added or updated for behavior changes
- [ ] `python -m pytest -q` passes locally

## Test Plan

<!-- Commands run, matrix coverage, packaging smoke if applicable. -->

```bash
python -m pytest -q
```

## Related

<!-- Fixes #NNN, relates to docs/oss/ gate IDs, etc. -->
