# Audit — hello_fortran

2 finding(s); 0 blocker(s), 1 high severity.

passed: **False**

- **[medium]** assumption_risk @ 1 function(s): 1 functions carry ≥5 rewrite assumptions; each is a potential divergence.  → _audit assumption lists; run #17 on each_
- **[high]** module_coherence @ hello_fortran: Only 2 of 7 binary functions were recovered.  → _rewrite more functions before publish_