# Figure captions and insights

## fig1_coverage

**Insight.** Three of the four sources cover almost every KEV CVE; the expert ATT&CK mapping (PKEV) covers only 419 of 1,391 (30%).

*Figure 1. Coverage of the 1,391 CISA KEV vulnerabilities by each integrated source. Orange = the gap that limits every ATT&CK analysis below.*

## fig2_time

**Insight.** KEV growth peaked in 2022; the share of CVEs with an ATT&CK mapping is uneven over time (18% to 81%), highest for the newest entries.

*Figure 2. (a) CVEs added to KEV per year, split by known ransomware use. (b) Share of each year's CVEs that PKEV maps to ATT&CK. The uneven coverage is a property of the mapping, not of the vulnerabilities [cause not tested].*

## fig3_vendors_cwe

**Insight.** One vendor, Microsoft, accounts for 24% of KEV and for 34% of the ransomware-linked entries; the weaknesses are dominated by memory-safety and injection classes.

*Figure 3. (a) Ten vendors with most KEV entries; orange = part with known ransomware use. (b) Ten most frequent weaknesses assigned by KEV (CVEs per CWE). CWE names from the MITRE list.*

## fig4_severity

**Insight.** KEV entries are mostly HIGH or CRITICAL (median 8.8); CRITICAL is more frequent among ransomware-linked entries: +17 percentage points (95% bootstrap CI 11 to 24).

*Figure 4. (a) CVSS v3.1 base scores of KEV CVEs (1,389 with a score). (b) Share rated CRITICAL, with 95% bootstrap confidence intervals (10,000 resamples, seed 42). Association within KEV only: there is no non-KEV comparison group here.*

## fig5_attack

**Insight.** Exploitation mappings sit mostly in initial-access (259) and execution (102); primary impacts in execution (179). The two most used techniques, T1059 and T1190, appear in 170 and 157 of the 419 mapped CVEs.

*Figure 5. (a) Twelve most used ATT&CK techniques, as distinct KEV CVEs, split by the role PKEV gives them. (b) Number of PKEV mappings per tactic and role (a technique that belongs to several tactics counts once per tactic; empty cells blank).*

## fig6_cooccurrence

**Insight.** Techniques are not independent: 77 pairs of the 30 most used techniques appear together in at least 3 CVEs, around a hub of T1190.

*Figure 6. Technique co-occurrence network (30 most used techniques; edge = at least 3 KEV CVEs mapped to both; edge width = number of shared CVEs, node size = number of CVEs, colour = most frequent role). Circular layout, grouped by role and ordered by size.*

## fig7_exploit_to_impact

**Insight.** The most common attack story in KEV is T1190 (Exploit Public-Facing Application) followed by T1059 (Command and Scripting Interpreter): 63 CVEs, 18% of the 345 CVEs that have both roles mapped.

*Figure 7. Directed network from the exploitation technique to the primary-impact technique of the same CVE (pairs shared by at least 5 CVEs; edge width and labels = number of CVEs; labels from 10). Built from PKEV, so only the 419 mapped CVEs can appear.*

## fig8_hubs_coverage

**Insight.** The CVE-technique network is one connected block (99% of nodes) with a heavy-tailed hub structure: the first 2 techniques already touch 61% of the mapped CVEs and 5 touch 82%.

*Figure 8. (a) Rank-frequency plot of techniques (log-log): number of CVEs mapped to each technique. (b) Cumulative share of mapped CVEs touched by the first k techniques, chosen greedily (set-cover heuristic) or simply most-used first.*

## fig9_case_study

**Insight.** CVE-2024-34102 (Adobe Commerce and Magento Open Source) is a single node that carries facts from four sources: KEV says it is exploited, NVD scores it 9.8, 3 PKEV mapping(s) say how, ATT&CK places them in 3 tactic(s).

*Figure 9. One vulnerability across the four sources. Blue = CISA KEV, orange = NVD, aqua = ATT&CK (techniques via the PKEV mapping, then tactics), gray = weakness (CWE). Function case_figure(cve_id) draws the same figure for any CVE.*
