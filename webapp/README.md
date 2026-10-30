# webapp/ — Phase 3: relational model in Django (serving layer)

Reads the **clean** CSV tables (`data/clean/`) into SQLite through Django models
(9 clean tables + 1 derived table `Cwe` = 10 models). Same workflow as the insurance example of the course.

## Files
| File | Where it goes |
|---|---|
| `catalog/models.py` | the 10 models (UML → ORM) |
| `catalog/admin.py` | admin site (list_display, filters, search) |
| `catalog/management/commands/load_clean_data.py` (+ the two `__init__.py`) | loader: clean CSV → DB (atomic, idempotent) |
| `threatgraph_site/urls.py`, `views.py` | `/admin/`, `/stats/`, `/vulnerability/<CVE>/` |
| `make_uml.py` | draws `docs/uml_threatgraph.png` from the models |

## Setup (from the project root, conda env active, `pip install -r requirements.txt` done)
```bash
django-admin startproject threatgraph_site webapp
cd webapp
python manage.py startapp catalog
# copy models.py + admin.py + management/ into catalog/ ; urls.py + views.py into threatgraph_site/
# settings.py -> INSTALLED_APPS: add 'catalog'
python manage.py makemigrations catalog
python manage.py migrate
python manage.py load_clean_data          # reads ../data/clean, prints 12,112 rows
python manage.py createsuperuser
python manage.py runserver                # http://127.0.0.1:8000/admin/  /stats/  /vulnerability/CVE-2024-34102/
python make_uml.py                        # -> ../docs/uml_threatgraph.png
```
`load_clean_data` can be run again at any time: it empties the tables and reloads them (same result).

## Check
`notebooks/04_django_models_and_loading.ipynb` runs the whole gate (20 checks + negative tests, including
DB → CSV bytes hash == `data/clean/manifest.json`) and writes `docs/phase3_validation_report.json`.

## Not covered yet (Phase 4+)
REST API (DRF), JSON-LD, snapshots/diff, plots.
