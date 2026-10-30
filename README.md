# ThreatGraph-LD

Unify four **open cyber-threat datasets** into one documented, versioned and FAIR-oriented data system
(Advanced Data Management course project, LM DSAI, UniTS).

| Source | What it is | Pinned version |
|---|---|---|
| **KEV** (CISA) | Vulnerabilities known to be exploited | catalog 2025.07.28 (1,391 CVEs) |
| **NVD** (NIST, via community mirror) | Full CVE description, CVSS, CWE, references | tag `v2025.07.28-000002` |
| **ATT&CK** (MITRE) | Attacker techniques/tactics, STIX 2.1 | Enterprise 16.1 |
| **PKEV** (CTID Mappings Explorer) | Expert mapping KEV CVE → ATT&CK technique | kev-07.28.2025 + attack-16.1 |

**Status: Phase 1 of 6 implemented and validated. Phases 2–6 are conceptual (stubs only).**

---

## Project phases

| Phase | Content | Status | Notebook |
|---|---|---|---|
| 1 | Download pinned raw data + validate (existence, integrity, format, timestamps, accessibility) | ✅ implemented and run | `01_download_data.ipynb` |
| 2 | Profile and clean → `data/clean/` | 🔲 concept only | `02_profile_and_clean` |
| 3 | Django models (UML → ORM) and loading | 🔲 concept only | `03_django_models_and_loading` |
| 4 | REST API + JSON-LD + Python client | 🔲 concept only | `04_…`, `05_api_and_client_tests` |
| 5 | Snapshots, hashes, diff | 🔲 concept only | `06_snapshot_jsonld_diff` |
| 6 | Results, plots, presentation | 🔲 concept only | `07_results_and_plots` |

Rule: **one phase at a time.** Phase *n+1* starts only when the Phase *n* gate (all checks green) has passed.

---

## Folder structure

```
threatgraph-ld/
├── README.md  LICENSE.txt  environment.yml  requirements.txt  .gitignore
├── config/
│   └── sources.yaml            # registry: URLs pinned to commits, expected SHA-256, counts, known anomalies
├── data/
│   ├── raw/                    # downloaded, read-only, never edited   (Phase 1)
│   │   ├── kev/  attack/  pkev/  nvd/cve/   # nvd/cve/ = 1,391 files, one per KEV CVE
│   │   ├── manifest.json                    # provenance: url, bytes, sha256, retrieved_at, license (versioned in git)
│   │   └── phase1_validation_report.json    # result of the gate (versioned in git)
│   ├── clean/                  # (Phase 2)
│   └── snapshots/              # (Phase 5)
├── src/threatgraph/            # reusable code: functions and classes only
│   ├── config.py integrity.py manifest.py download.py validate_raw.py peek.py   # IMPLEMENTED
│   └── profiling.py cleaning.py jsonld.py snapshot.py api_client.py plots.py    # CONCEPTUAL STUBS
├── notebooks/                  # executable steps: import, run, test, show
│   └── 01_download_data.ipynb  # IMPLEMENTED (outputs included)
├── webapp/                     # Django project (Phase 3, not created yet) – see webapp/README.md
└── docs/                       # DMP and report (later)
```

**Convention.** `.py` = definitions (functions, classes, utilities, plots). `.ipynb` = *use* them: run, check, show.

---

## Setup (conda)

```bash
conda env create -f environment.yml
conda activate threatgraph
python -m ipykernel install --user --name threatgraph --display-name "Python (threatgraph)"
jupyter lab            # then open notebooks/01_download_data.ipynb
```

Without conda: `python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`.

Needs: internet access to `raw.githubusercontent.com` (preflight cell checks it) and about 70 MB of disk.

## Phase 1 — usage

Interactive: open `notebooks/01_download_data.ipynb` and run all cells.
Headless:

```bash
cd notebooks
jupyter nbconvert --to notebook --execute 01_download_data.ipynb --output 01_download_data.ipynb
```

What the notebook does: preflight (HEAD on all URLs) → download core files (idempotent) → derive the CVE list from KEV →
download 1,391 NVD records (8 threads, retry/back-off) → write `manifest.json` → show each format → run the five validation
families → negative tests on deliberately damaged copies → write `phase1_validation_report.json` (**the gate**).

### Design choices (and why)

* **Pinned by commit, not by branch** – reproducibility; the same URL returns the same bytes.
* **SHA-256 expected in the registry** – detects corruption *and* silent upstream change (fixity, OAIS).
* **`.part` file + atomic rename** – a crash never leaves a half file with the final name.
* **`Accept-Encoding: identity`** – `Content-Length` equals the bytes on disk, so truncation is detectable.
* **Cache + idempotency** – re-running downloads nothing if hashes match.
* **Raw files are read-only** (mode `0444`) – raw data is immutable; cleaning writes to `data/clean/`.
* **Manifest** – one provenance record per file (what, from where, when, which hash, which license).
* **NVD from a community mirror** – `nvd.nist.gov` was not reachable from the build sandbox, so the unofficial mirror `fkie-cad/nvd-json-data-feeds` is used. [UNCERTAIN] fidelity vs. official NVD beyond the checks.

### What is validated

| Family | Examples of checks |
|---|---|
| Existence | every registry file present & non-empty; exactly one NVD file per KEV CVE; no stray `.part` |
| Integrity | SHA-256 and size vs registry and vs manifest; NVD canary hash |
| Format | JSON parses; KEV 1,391 × 11 fields & types; PKEV 1,183 rows / 419 CVEs / 155 techniques; ATT&CK STIX 2.1, 22,905 objects, 799 techniques; NVD keys; PKEV CVEs ⊆ KEV and PKEV techniques ⊆ ATT&CK |
| Timestamps | KEV `catalogVersion`/`dateReleased`; ATT&CK collection version 16.1; PKEV `attack_version`; every NVD `lastModified` ≤ 2025-07-28; retrieval times in range |
| Accessibility | files readable, mode read-only, large file parses fast, online preflight (HTTP 200) |

### Known anomalies in the source data (not code bugs)

* KEV: 15 entries (all added 2021-11-03) have `dueDate` earlier than `dateAdded`.
* ATT&CK 16.1: 2 `relationship` objects have `created` later than `modified`.

Both are asserted with their exact counts (`known_anomalies` in `config/sources.yaml`).

### Limits of the Phase-1 validation

* It proves the files are the pinned bytes and structurally as expected, **not** that the upstream facts are correct.
* The negative tests damage *copies/in-memory documents*; they show the checks can fail, not that every possible corruption is caught.
* Tested with Python 3.13 in a Linux sandbox. `environment.yml` pins Python 3.11 but **has not been run** (conda was not available there).

---

## Data licenses (the code license does NOT apply to the data)

| Source | License / terms | Note |
|---|---|---|
| KEV | CC0-1.0 (repo) | copy in `data/raw/kev/LICENSE` |
| NVD / CVE | public data under NVD/CVE terms of use | copies in `data/raw/nvd/` |
| ATT&CK | MITRE ATT&CK Terms of Use | copy in `data/raw/attack/LICENSE.txt` |
| PKEV | Apache-2.0 on the repository | no separate data license stated [UNCERTAIN] |

## Code license

MIT, see `LICENSE.txt`. **Replace the copyright-holder placeholder** with your name before publishing.

## Final usage section

_To be completed at the end of the project (end-to-end run: Django loading, API, JSON-LD, snapshots, results)._
