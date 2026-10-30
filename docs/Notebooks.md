# notebooks/

Notebooks **run** things (import, call, test, show). Reusable code is in `src/threatgraph/`.
Each notebook ends with a *gate*: if an assert fails, the next phase does not start.

| Notebook | Phase | Status | Purpose | Gate |
|---|---|---|---|---|
| `01_download_data.ipynb` | 1 | ✅ implemented | download pinned raw data, show formats, validate | existence, integrity, format, timestamps, accessibility |
| `02_profile_and_clean.ipynb` | 2 | concept | profile each source (nulls, types, duplicates), apply cleaning rules → `data/clean/` | row counts in/out reconcile; schema validation |
| `03_django_models_and_loading.ipynb` | 3 | concept | create the Django models, load `clean/` into SQLite, spot-check | DB counts == clean counts; FK integrity |
| `04_coverage_report.ipynb` | 3 | concept | how many KEV CVEs have NVD data / ATT&CK mapping | numbers match hand-computed reference |
| `05_api_and_client_tests.ipynb` | 4 | concept | call the REST API with `api_client.py`; JSON and JSON-LD | status codes, content negotiation, JSON-LD parses to triples |
| `06_snapshot_jsonld_diff.ipynb` | 5 | concept | freeze a snapshot, hash it, diff against another | hash reproducible; diff correct on a synthetic change |
| `07_results_and_plots.ipynb` | 6 | concept | figures and tables for report and slides | figures regenerate from scratch |

Run headless: `jupyter nbconvert --to notebook --execute 01_download_data.ipynb --output 01_download_data.ipynb`
