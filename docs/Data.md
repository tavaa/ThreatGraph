# data/

| Folder | Content | Written by | Mutable? |
|---|---|---|---|
| `raw/` | files exactly as downloaded from the pinned URLs | Phase 1 (`download.py`) | **No** – read-only (0444) |
| `clean/` | normalised tables derived from `raw/` | Phase 2 | regenerated, never edited by hand |
| `snapshots/` | frozen, hashed exports of the database | Phase 5 | append-only |

`raw/manifest.json` records, for every file: source, role, relative path, URL, bytes, SHA-256, retrieval time (UTC),
HTTP status, license, pinned commit. `raw/phase1_validation_report.json` is the result of the Phase-1 gate.

Raw data files are **not versioned in git** (they are reproducible from `config/sources.yaml`); the manifest and the report are.
To re-create the folder: run `notebooks/01_download_data.ipynb`.
