---
name: New scenario / feature request
about: Suggest a new attack variant, scenario, or feature
title: "[FEATURE] "
labels: enhancement
---

**What are you proposing?**
e.g. "A second A05 variant demonstrating command injection, not just SQLi/XSS"

**Which OWASP Top 10:2025 category does this map to (if applicable)?**

**Why does this add value beyond what's already covered?**
Check `docs/OWASP_MAPPING.md` first — what's genuinely new here vs. an
existing scenario?

**Is this genuinely exploitable against real code, or would it need to be simulated?**
Per `CONTRIBUTING.md`, real exploitability (real DB queries, real
verification logic, etc.) is strongly preferred over simulated checks. If
it needs to be simulated for safety (like this project's SSRF and
integrity-failure scenarios), explain why.

**Rough implementation sketch (optional)**
