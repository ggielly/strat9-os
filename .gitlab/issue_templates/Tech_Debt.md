---
name: Tech Debt
about: Known design limitation, workaround, or suboptimal implementation to revisit
labels: refactor
---

## Location

- **File(s):** <!-- e.g. workspace/kernel/src/memory/buddy.rs -->
- **Function / struct:** 

## Problem

<!-- What is wrong or suboptimal? Why is it a problem now or in the future? -->

## Current workaround

<!-- How is the issue mitigated today? Is it safe short-term? -->

## Recommended direction

<!-- What should replace it? Keep it concrete. -->

## Risk if left unaddressed

- [ ] Correctness — could cause bugs or UB
- [ ] Performance — measurable overhead on hot path
- [ ] Maintainability — makes future changes harder
- [ ] Safety — unsafe invariant not enforced
- [ ] Low — cosmetic / documentation only

## Priority

- [ ] Must fix before milestone
- [ ] Medium — fix in a dedicated pass
- [ ] Low — acceptable as-is for now
