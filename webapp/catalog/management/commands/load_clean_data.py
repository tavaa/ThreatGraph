"""python manage.py load_clean_data [--clean-dir PATH]

Loads data/clean/*.csv into the database. Idempotent: deletes everything in the 10 tables and reloads inside
ONE transaction (all or nothing). Typed reading is delegated to threatgraph.cleaning.read_clean, so the
schema of the CSV files has a single source of truth.
"""
import sys
from pathlib import Path

import pandas as pd
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

ROOT = Path(__file__).resolve().parents[4]          # webapp/catalog/management/commands/ -> repo root
sys.path.insert(0, str(ROOT / "src"))

from threatgraph import cleaning as C                # noqa: E402

from catalog.models import (AttackTactic, AttackTechnique, AttackTechniqueTactic, Cwe, KevCwe, NvdCveCwe,  # noqa: E402
                            NvdRecord, PkevMapping, PkevMappingReference, Vulnerability)

# clean table -> (model, clean columns that are NOT stored on that model)
TABLES = {
    "kev_vulnerability": (Vulnerability, set()),
    "kev_cwe": (KevCwe, set()),
    "nvd_cve": (NvdRecord, set()),
    "nvd_cve_cwe": (NvdCveCwe, {"is_informative"}),      # moved to Cwe (3NF)
    "attack_tactic": (AttackTactic, set()),
    "attack_technique": (AttackTechnique, set()),
    "attack_technique_tactic": (AttackTechniqueTactic, set()),
    "pkev_mapping": (PkevMapping, set()),
    "pkev_mapping_reference": (PkevMappingReference, set()),
}
DELETE_ORDER = [PkevMappingReference, PkevMapping, AttackTechniqueTactic, AttackTechnique, AttackTactic, NvdCveCwe,
                NvdRecord, KevCwe, Vulnerability, Cwe]


def py(value, dtype):
    """pandas/numpy value -> plain Python (NA -> None)."""
    if pd.isna(value):
        return None
    if dtype == "date":
        return value.date()
    if dtype == "datetime":
        return value.to_pydatetime()
    return {"int": int, "float": float, "bool": bool}.get(dtype, str)(value)


def records(df, table, model, dropped):
    spec = C.SCHEMA[table]
    attnames = {f.attname for f in model._meta.concrete_fields}
    unknown = set(df.columns) - attnames - dropped
    if unknown:
        raise CommandError(f"{table}: CSV columns with no model field: {sorted(unknown)}")
    cols = [c for c in df.columns if c in attnames]
    for row in df[cols].itertuples(index=False):
        yield model(**{c: py(v, spec.columns[c].dtype) for c, v in zip(cols, row)})


class Command(BaseCommand):
    help = "Load data/clean/*.csv into the database (idempotent, one transaction)."

    def add_arguments(self, parser):
        parser.add_argument("--clean-dir", default=str(ROOT / "data" / "clean"))

    @transaction.atomic
    def handle(self, *args, **opts):
        clean_dir = Path(opts["clean_dir"])
        tables = {t: C.read_clean(t, clean_dir) for t in TABLES}
        AttackTechnique.objects.update(parent_technique=None)     # self-FK is PROTECT: detach before deleting
        for model in DELETE_ORDER:
            model.objects.all().delete()
        # Cwe is derived: every cwe_id used by KEV or NVD; informative unless NVD's "no info"/"other" labels.
        ids = sorted(set(tables["kev_cwe"].cwe_id) | set(tables["nvd_cve_cwe"].cwe_id))
        Cwe.objects.bulk_create([Cwe(cwe_id=i, is_informative=i not in C.NONINFORMATIVE_CWE) for i in ids])
        counts = {"Cwe": len(ids)}
        for table, (model, dropped) in TABLES.items():
            objs = list(records(tables[table], table, model, dropped))
            model.objects.bulk_create(objs, batch_size=500)
            counts[model.__name__] = len(objs)
        for name, n in counts.items():
            self.stdout.write(f"  {name:24s} {n:>6,d}")
        self.stdout.write(self.style.SUCCESS(f"loaded {sum(counts.values()):,} rows from {clean_dir}"))
