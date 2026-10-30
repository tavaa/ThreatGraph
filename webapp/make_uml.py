"""Draw the UML class diagram of catalog/models.py and save it as a PNG.

    cd webapp && python make_uml.py            # -> ../docs/uml_threatgraph.png

Classes, primary keys, foreign keys and multiplicities are READ FROM THE DJANGO MODELS (introspection), so the
picture cannot drift away from the code. Only the choice of the extra attributes to show (SHOW) and the layout
(POS) are hand-written. Needs: django, matplotlib. No Graphviz.
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "threatgraph_site.settings")

import django  # noqa: E402

django.setup()

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from django.apps import apps  # noqa: E402
from django.db import models  # noqa: E402
from matplotlib.patches import FancyBboxPatch, Rectangle  # noqa: E402

OUT = HERE.parent / "docs" / "uml_threatgraph.png"

SOURCE = {"Vulnerability": "KEV", "KevCwe": "KEV", "NvdRecord": "NVD", "NvdCveCwe": "NVD", "Cwe": "derived",
          "AttackTactic": "ATT&CK", "AttackTechnique": "ATT&CK", "AttackTechniqueTactic": "ATT&CK",
          "PkevMapping": "PKEV", "PkevMappingReference": "PKEV"}
COLOUR = {"KEV": "#dbe8f7", "NVD": "#dcefd9", "ATT&CK": "#e6dcf2", "PKEV": "#fbe7cf", "derived": "#e4e4e4"}
EDGE = {"KEV": "#3b6ea5", "NVD": "#4f8a3f", "ATT&CK": "#7a55a3", "PKEV": "#c9822b", "derived": "#777777"}

# extra attributes to show (keys and relations are added automatically)
SHOW = {
    "Vulnerability": ["vendor_project", "product", "date_added", "ransomware_use", "due_before_added"],
    "Cwe": ["is_informative"],
    "KevCwe": [],
    "NvdRecord": ["vuln_status", "published", "cvss_v31_score", "cvss_v31_severity", "cvss_v31_type", "cvss_v2_score"],
    "NvdCveCwe": ["source", "type"],
    "AttackTactic": ["shortname", "name"],
    "AttackTechnique": ["name", "status", "is_subtechnique"],
    "AttackTechniqueTactic": [],
    "PkevMapping": ["mapping_type", "capability_group", "comments"],
    "PkevMappingReference": ["reference", "is_http_url"],
}
# top-left corner of each box in diagram units (canvas 134 x 100); box width W
W, LINE, HEAD = 24.5, 2.0, 3.4
POS = {"KevCwe": (3, 93), "Cwe": (3, 72), "NvdCveCwe": (3, 54),
       "Vulnerability": (38, 93), "NvdRecord": (38, 58),
       "PkevMapping": (74, 93), "PkevMappingReference": (74, 62),
       "AttackTechnique": (109, 93), "AttackTechniqueTactic": (109, 66), "AttackTactic": (109, 48)}

TYPE = {models.CharField: "str", models.TextField: "text", models.DateField: "date", models.DateTimeField: "datetime",
        models.FloatField: "float", models.BooleanField: "bool", models.PositiveIntegerField: "int",
        models.IntegerField: "int"}


def ftype(f):
    for cls in type(f).__mro__:
        if cls in TYPE:
            return TYPE[cls]
    return type(f).__name__


def box_lines(model):
    """UML attribute lines, read from the model."""
    lines = []
    fks = {f.name: f for f in model._meta.concrete_fields if f.is_relation}
    for f in model._meta.concrete_fields:
        if f.primary_key:
            lines.append((f"+ {f.name}" + (" (FK)" if f.is_relation else f" : {ftype(f)}") + "  {PK}", True))
    for f in fks.values():
        if not f.primary_key:
            tgt = "self" if f.related_model is model else f.related_model.__name__
            lines.append((f"+ {f.name} -> {tgt}", False))
    for name in SHOW[model.__name__]:
        f = model._meta.get_field(name)
        lines.append((f"+ {name} : {ftype(f)}" + ("?" if f.null else ""), False))
    return lines


def main():
    mods = {m.__name__: m for m in apps.get_app_config("catalog").get_models()}
    assert set(mods) == set(POS) == set(SOURCE) == set(SHOW), "models, layout and source map are out of sync"

    fig, ax = plt.subplots(figsize=(17, 12.6))
    ax.set_xlim(0, 140)
    ax.set_ylim(22, 100)
    ax.set_aspect("equal")
    ax.axis("off")
    rect = {}

    for name, m in mods.items():
        src = SOURCE[name]
        lines = box_lines(m)
        x, y = POS[name]
        h = HEAD + LINE * len(lines) + 0.8
        rect[name] = (x, y - h, W, h)
        ax.add_patch(FancyBboxPatch((x, y - h), W, h, boxstyle="round,pad=0,rounding_size=0.6", fc=COLOUR[src],
                                    ec=EDGE[src], lw=1.6, zorder=2))
        ax.add_patch(Rectangle((x, y - HEAD), W, HEAD, fc=EDGE[src], ec=EDGE[src], zorder=3))
        is_assoc = name in {"KevCwe", "NvdCveCwe", "AttackTechniqueTactic", "PkevMapping"}
        title = ("«assoc» " if is_assoc else "") + name
        ax.text(x + W / 2, y - HEAD / 2, title, ha="center", va="center", color="white",
                fontsize=9.5 if len(title) <= 24 else 8.2, weight="bold", zorder=4)
        for i, (t, is_pk) in enumerate(lines):
            ax.text(x + 0.9, y - HEAD - LINE * (i + 0.6), t, ha="left", va="center", fontsize=7.6, zorder=4,
                    family="DejaVu Sans Mono", weight="bold" if is_pk else "normal")

    def anchor(a, b):
        """Point on the border of box a, on the straight line to the centre of box b."""
        ax_, ay, aw, ah = rect[a]
        bx, by, bw, bh = rect[b]
        cx, cy, dx, dy = ax_ + aw / 2, ay + ah / 2, (bx + bw / 2) - (ax_ + aw / 2), (by + bh / 2) - (ay + ah / 2)
        t = min((aw / 2) / abs(dx) if dx else 1e9, (ah / 2) / abs(dy) if dy else 1e9)
        return cx + dx * t, cy + dy * t

    def label(p, q, text, side=1):
        x0, y0 = p
        x1, y1 = q
        L = ((x1 - x0) ** 2 + (y1 - y0) ** 2) ** 0.5 or 1
        ux, uy = (x1 - x0) / L, (y1 - y0) / L
        ax.text(x0 + ux * 2.2 - uy * 1.3 * side, y0 + uy * 2.2 + ux * 1.3 * side, text, fontsize=8.5, ha="center",
                va="center", color="#222", zorder=5, bbox=dict(fc="white", ec="none", pad=0.4, alpha=0.85))

    for name, m in mods.items():
        for f in m._meta.concrete_fields:
            if not f.is_relation:
                continue
            target = f.related_model.__name__
            if target == name:       # self reference (parent technique): small loop on the right-hand side
                x, y, w, h = rect[name]
                ax.annotate("", xy=(x + w, y + h * 0.25), xytext=(x + w, y + h * 0.65),
                            arrowprops=dict(arrowstyle="-|>", color="#333", lw=1.2, connectionstyle="arc3,rad=-1.6"), zorder=1)
                ax.text(x + w + 2.6, y + h * 0.45, "parent 0..1\nsub *", fontsize=7.5, va="center", ha="left")
                continue
            p, q = anchor(name, target), anchor(target, name)
            one_to_one = isinstance(f, models.OneToOneField)
            ax.annotate("", xy=q, xytext=p, arrowprops=dict(arrowstyle="-|>", color="#333", lw=1.2, shrinkA=0, shrinkB=0), zorder=1)
            label(p, q, "1" if one_to_one else "*")
            label(q, p, "0..1" if one_to_one else ("0..1" if f.null else "1"), side=-1)

    ax.text(67, 99.3, "ThreatGraph-LD: class diagram (Django models, drawn from the code)", ha="center", va="center",
            fontsize=14, weight="bold")
    lx = 3
    for k in ("KEV", "NVD", "ATT&CK", "PKEV", "derived"):
        ax.add_patch(Rectangle((lx, 26.6), 3, 2, fc=COLOUR[k], ec=EDGE[k], lw=1.4))
        ax.text(lx + 4, 27.6, k, fontsize=9, va="center")
        lx += 17
    ax.text(3, 23.6, "Notation: «assoc» = association class (Django 'through' model) | * = many | 1 = exactly one | 0..1 = optional | "
            "x? = NULL allowed | {PK} = primary key | arrow = foreign key (from child to parent)",
            fontsize=8, va="center", color="#333")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=130, bbox_inches="tight", facecolor="white")
    print("saved", OUT)


if __name__ == "__main__":
    main()
