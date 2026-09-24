# SecureMe Cisco Hardening Upgrade

This build replaces the old 4-control Cisco demo evaluation with the expanded Cisco hardening catalog.

## What changed
- Cisco parser: deterministic security inventory and parser coverage statistics.
- Cisco compliance catalog: 88 Cisco hardening controls in the catalog, with conditional routing controls evaluated only when the protocol is present.
- Pipeline: production Cisco analysis evaluates `cisco:ios-hardening` controls instead of the temporary `DEMO` controls.
- Dashboard: existing findings view now renders the full finding list and dynamic control count.
- PDF/API dependencies are retained.
- AI remains enrichment-only; it does not decide PASS/FAIL.

## Current c2911 fixture result
- 592 source lines
- 476 recognized non-empty configuration lines
- 4 unknown configuration lines
- 99.17% parser coverage
- 77 applicable/evaluable Cisco hardening controls for this configuration

The exact PASS/FAIL/UNKNOWN result is configuration-dependent and is generated deterministically by the rule engine.

## Deploy
1. Replace the files in the patch ZIP in your project.
2. Run `python -m pytest -q`.
3. Commit and push to GitHub.
4. Let Render redeploy.
5. Upload `c2911-router.conf` again; do not rely on the old analysis result.
