---
name: test-driven-development
description: Use when implementing a feature or fixing a bug that has testable behavior. Red, green, refactor in small steps.
---

# Test-driven development

Use for logic with testable behavior. Skip for pure config, docs, or throwaway scripts.

1. **Red:** write one small failing test that describes the next behavior. Run only that test; confirm it fails for the right reason (not a typo or import error).
2. **Green:** write the minimum code to pass. No extra features, no speculative abstractions.
3. **Refactor:** clean up with tests green; no behavior change.
4. Repeat in small increments. Commit-sized steps.

Rules:
- Test behavior through public interfaces, not private internals.
- One reason to fail per test; descriptive names.
- Mock only external boundaries (network, clock, filesystem), not your own code.
- Never weaken or delete a test to make it pass; fix the code or ask.
- Run the single test during the loop, the full suite once before finishing.
