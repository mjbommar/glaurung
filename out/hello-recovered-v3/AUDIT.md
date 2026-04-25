# Audit — hello

3 finding(s); 0 blocker(s), 1 high severity.

passed: **False**

- **[medium]** confidence_gap @ 2 function(s): 2 functions were rewritten with <0.4 confidence — manual review recommended.  → _re-run rewrite with richer caller context or review by hand_
- **[medium]** assumption_risk @ 3 function(s): 3 functions carry ≥5 rewrite assumptions; each is a potential divergence.  → _audit assumption lists; run #17 on each_
- **[high]** module_coherence @ hello: Only 3 of 12 binary functions were recovered.  → _rewrite more functions before publish_