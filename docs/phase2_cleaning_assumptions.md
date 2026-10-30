# Phase 2 — Cleaning: concept and assumptions

Status: implemented and validated (`notebooks/02_clean_data.ipynb`, `notebooks/03_validate_clean_data.ipynb`).
Counts below were **measured** on the pinned raw data (2025-07-28 snapshot); they are pinned in `config/sources.yaml → expected_clean`.
Labels: [LITERATURE] supported by a source · [INFERENCE] my reasoning · [PROPOSAL] a design choice · [UNCERTAIN] not verified.

## 1. Concept

**Goal.** Turn four heterogeneous raw files (KEV: flat JSON; NVD: 1,391 nested JSON; PKEV: JSON with lists; ATT&CK: a STIX graph)
into **10 flat, typed, relational tables** that a database can load without surprises — without touching raw and without losing the trace to it.

**Data-lake reading.** Three zones: `raw` (immutable, hashed) → `clean` (this phase) → `serving` (Django, Phase 3). [INFERENCE: standard lake layering, adapted]
Cleaning is a *function of raw only*: same raw + same code ⇒ same bytes (the clean manifest stores SHA-256 of every table and of `cleaning.py`).

**What "clean" means here.** Consistent and traceable — *not* "true". We do not fix facts, we make them uniform and comparable and we record every decision.

**Three kinds of problem, three different treatments**

| Kind | Example | Treatment |
|---|---|---|
| *Missing* | KEV `cwes = []`, PKEV `comments = null`, NVD without CVSS v3.1 | stays missing (`NULL` / no row); never imputed |
| *Messy form* | trailing spaces, dates/timestamps in different shapes, lists | normalise form only (strip, ISO dates, link tables) |
| *Inconsistent* | KEV `dueDate` before `dateAdded`; KEV vs NVD CWE disagree; dirty PKEV references | keep the original value, **flag** or **report**; never overwrite |

## 2. Raw files needed (inputs of Phase 2)

| Source | File | Role |
|---|---|---|
| KEV | `data/raw/kev/known_exploited_vulnerabilities.json` | scope: 1,391 CVEs |
| NVD | `data/raw/nvd/cve/CVE-*.json` ×1,391 | description, CVSS, CWE |
| ATT&CK | `data/raw/attack/enterprise-attack-16.1.json` | techniques and tactics |
| PKEV | `data/raw/pkev/kev-07.28.2025_attack-16.1-enterprise.json` | CVE → technique mappings |
| (check only) | `data/raw/manifest.json` | proves raw is untouched (G1) |

Code files: `src/threatgraph/cleaning.py` (rules, schema, writer), `profiling.py` (evidence), `validate_clean.py` (gate).

## 3. Output tables (clean layer, `data/clean/*.csv`)

| Table | Primary key | Rows | From | Note |
|---|---|---|---|---|
| `kev_vulnerability` | cve_id | 1,391 | KEV | + `due_before_added`, `src_row` |
| `kev_cwe` | (cve_id, cwe_id) | 1,328 | KEV `cwes` | list → rows |
| `nvd_cve` | cve_id | 1,391 | NVD | CVSS v3.1 columns nullable |
| `nvd_cve_cwe` | (cve_id, cwe_id, source) | 2,523 | NVD `weaknesses` | `is_informative` |
| `attack_tactic` | tactic_id | 14 | ATT&CK | |
| `attack_technique` | technique_id | 799 | ATT&CK | `status` active/revoked/deprecated, parent |
| `attack_technique_tactic` | (technique_id, tactic_id) | 1,051 | ATT&CK phases | many-to-many |
| `pkev_mapping` | mapping_id | 1,183 | PKEV | association CVE–technique, unique (cve, technique, type) |
| `pkev_mapping_reference` | (mapping_id, reference) | 2,256 | PKEV `references` | `is_http_url` |

Format: CSV, UTF-8, LF, deterministic row order; `NULL` = empty cell; dates `YYYY-MM-DD`; timestamps UTC `YYYY-MM-DDTHH:MM:SS.mmmZ`.
Why CSV [PROPOSAL]: no extra dependency, readable, diff-able, loads straight into Django; the schema (types, keys) lives in `cleaning.SCHEMA`.

## 4. Assumptions (each is a numbered rule in the code, counted in the clean manifest)

### General
| ID | Assumption | Why | Risk / alternative |
|---|---|---|---|
| G1 | Raw is never modified; cleaning starts only if all 1,401 raw files match the Phase-1 manifest | reproducibility, fixity | none; fail-loud |
| G2 | Missing ≠ empty. Blank string → `NULL`; absent list → zero rows; no imputation | a fake `""`/`0` is indistinguishable from data | downstream must handle NULL |
| G3 | No cross-source imputation; disagreements are reported only | two sources = two opinions; provenance stays clear | coverage lower than with merging |
| G4 | Only edge whitespace is stripped (559 values) | trailing spaces break joins/comparisons (e.g. PKEV vs KEV name) | no case/unicode normalisation: near-duplicates would survive |
| G5 | KEV dates have no zone; NVD timestamps have none either and are **assumed UTC**; ATT&CK is UTC | needed to compare instants | [UNCERTAIN] NVD zone not verified here; ≤ a few hours' error |
| G6 | Scope = the 1,391 KEV CVEs; unknown vocabulary values abort cleaning | silent acceptance hides drift | a new upstream value needs a human decision |

### KEV
| ID | Assumption | Evidence (measured) |
|---|---|---|
| K1 | `knownRansomwareCampaignUse` → enum {known, unknown}; **unknown ≠ false** | 291 known / 1,100 unknown |
| K2 | `cwes = []` → no rows in `kev_cwe`; not filled from NVD | 148 CVEs |
| K3 | `dueDate < dateAdded` kept as is, `due_before_added = true` | 15 entries, all added 2021-11-03 (bulk load) |

### NVD
| ID | Assumption | Evidence |
|---|---|---|
| N1 | One row per CVE; description = the English one | exactly 1 per CVE |
| N2 | Only CVSS v3.1 in `cvss_v31_*`: **Primary** metric if present, else first Secondary (type stored). No v3.1 → NULL. v2 stored separately, never converted | 1,104 CVEs have several v3.1 metrics; 135 have only a CNA (Secondary) one; 2 have no v3.1 (only v2) |
| N3 | One row per distinct (CVE, CWE, source); `NVD-CWE-noinfo/Other` kept with `is_informative = false` | 373 rows non-informative |
| N4 | `vulnStatus` stored as given; "Deferred" ⇒ no NVD analysis, scores may be CNA-only | 316 Deferred |
| N5 | References only counted; CPE configurations not stored | out of scope for the KEV↔ATT&CK goal [PROPOSAL] |

### ATT&CK
| ID | Assumption | Evidence |
|---|---|---|
| T1 | Keep only `attack-pattern` and `x-mitre-tactic` | 799 + 14 kept; 22,092 other objects stay in raw |
| T2 | Revoked/deprecated techniques are kept with `status` | 131 revoked, 12 deprecated; PKEV maps none of them |
| T3 | `parent_technique_id` derived from the id; parent must exist | 456 sub-techniques, 0 orphans |
| T4 | Tactics from `kill_chain_phases` (`mitre-attack`) | every technique has ≥ 1 tactic; 1,051 links |

### PKEV
| ID | Assumption | Evidence |
|---|---|---|
| P1 | `mapping_id` = 1-based position in the source file | stable only for this pinned version |
| P2 | `comments = null` stays NULL | 5 rows |
| P3 | `references`: a string made only of whitespace/`;`-separated http(s) URLs is split [INFERENCE]; any other string is kept verbatim and flagged `is_http_url = false`; repeats dropped | 18 glued strings split; 25 non-URL strings (fragments like `Exploitation`, `[]`, text cut at commas); 5 repeats |
| P4 | `capability_description`, `attack_object_name` dropped (duplicates of KEV/ATT&CK) | differences: 0 (technique names), 3 rows / 1 CVE (KEV name) |
| P5 | PKEV covers a subset: no row ⇒ "not mapped", **not** "no technique applies" | 419 of 1,391 CVEs mapped (30%) |

## 5. Cross-source disagreements (reported, not repaired)

| Finding | Number | Meaning |
|---|---|---|
| KEV vs NVD informative CWE: identical sets | 863 of 1,148 | the rest differ |
| … sharing no CWE at all | 126 | different taxonomy depth or different opinion |
| KEV `dateAdded` earlier than NVD `published` | 55 | KEV can list a CVE before NVD publishes it |
| NVD missing the KEV echo fields | 3 | NVD mirror synced just before KEV's last update |
| NVD echo of KEV fields that differ | 0 | the two snapshots are aligned |
| PKEV technique name ≠ ATT&CK name | 0 | PKEV built on the same ATT&CK version |

## 6. How the clean layer is validated (notebook 03)
Six families — schema, keys (PK/unique/FK), domain, semantic, **independent recount from raw**, provenance — 152 checks, plus 14 negative tests on deliberately broken copies.
Limit: the recount is written by the same author as the rules; it catches coding errors, not wrong decisions. Decisions are the list above.

## 7. Exam questions this phase prepares
1. Why keep raw immutable and cleaning a pure function of raw? (fixity, reproducibility, OAIS)
2. NULL, empty list, `"unknown"`, `0`: when are they different facts?
3. Why a link table for `cwes` instead of a list column? (1NF, queries, foreign keys)
4. Two sources disagree on a CWE — what do you store, and why not "the best one"? (provenance, G3)
5. A CVE has no PKEV row: what can you claim? (open-world vs closed-world assumption)
6. Which checks would catch a silently lost row? (reconciliation against an independent count)
