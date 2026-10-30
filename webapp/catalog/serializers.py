"""REST representations (Phase 4). Read-only.

The JSON-LD view (src/threatgraph/jsonld.py) is built FROM these dictionaries, so both formats say the same thing.
NULL is shown as null here (explicit "the source did not say"); the JSON-LD view omits it.
"""
from rest_framework import serializers

from .models import (AttackTactic, AttackTechnique, Cwe, PkevMapping, Vulnerability)


def iso(dt):
    """Aware datetime (UTC) -> '2024-05-01T12:00:00.123Z'."""
    return None if dt is None else dt.isoformat().replace("+00:00", "Z")


# ------------------------------------------------------------------ vulnerabilities ---------------------
class VulnerabilityListSerializer(serializers.ModelSerializer):
    """Small row for lists. ``n_mappings`` is annotated by the view (one SQL query for the whole page)."""
    url = serializers.HyperlinkedIdentityField(view_name="api-vulnerability-detail", lookup_field="cve_id")
    cvss_v31_score = serializers.FloatField(source="nvd.cvss_v31_score", read_only=True, default=None)
    cvss_v31_severity = serializers.CharField(source="nvd.cvss_v31_severity", read_only=True, default=None)
    n_mappings = serializers.IntegerField(read_only=True)

    class Meta:
        model = Vulnerability
        fields = ["url", "cve_id", "vendor_project", "product", "vulnerability_name", "date_added",
                  "ransomware_use", "cvss_v31_score", "cvss_v31_severity", "n_mappings"]


class VulnerabilityDetailSerializer(serializers.ModelSerializer):
    """One CVE seen through the four sources: KEV (own fields) + NVD + CWE + ATT&CK via PKEV."""
    url = serializers.HyperlinkedIdentityField(view_name="api-vulnerability-detail", lookup_field="cve_id")
    kev_cwes = serializers.SerializerMethodField()
    nvd = serializers.SerializerMethodField()
    attack = serializers.SerializerMethodField()
    attack_note = serializers.SerializerMethodField()

    class Meta:
        model = Vulnerability
        fields = ["url", "cve_id", "vendor_project", "product", "vulnerability_name", "date_added", "due_date",
                  "short_description", "required_action", "ransomware_use", "notes", "due_before_added",
                  "kev_cwes", "nvd", "attack", "attack_note"]

    @staticmethod
    def _cwe(c):
        return {"cwe_id": c.cwe_id, "is_informative": c.is_informative}

    def get_kev_cwes(self, v):
        return [self._cwe(c) for c in sorted(v.cwes.all(), key=lambda c: c.cwe_id)]

    def get_nvd(self, v):
        n = getattr(v, "nvd", None)
        if n is None:
            return None
        cvss = None
        if n.cvss_v31_score is not None:
            cvss = {"score": n.cvss_v31_score, "severity": n.cvss_v31_severity, "vector": n.cvss_v31_vector,
                    "source": n.cvss_v31_source, "type": n.cvss_v31_type}
        links = sorted(n.nvdcvecwe_set.all(), key=lambda x: (x.cwe_id, x.source))
        return {"status": n.vuln_status, "published": iso(n.published), "last_modified": iso(n.last_modified),
                "description_en": n.description_en, "cvss_v31": cvss, "cvss_v2_score": n.cvss_v2_score,
                "n_references": n.n_references,
                "cwes": [{"cwe_id": x.cwe_id, "is_informative": x.cwe.is_informative, "source": x.source,
                          "type": x.type} for x in links]}

    def get_attack(self, v):
        out = []
        for m in v.mappings.all():                       # ordered by mapping_id, prefetched by the view
            t = m.technique
            out.append({
                "mapping_id": m.mapping_id, "technique_id": t.technique_id, "technique_name": t.name,
                "technique_url": self.context["request"].build_absolute_uri(f"/api/techniques/{t.technique_id}/"),
                "tactics": [{"tactic_id": x.tactic_id, "shortname": x.shortname}
                            for x in sorted(t.tactics.all(), key=lambda x: x.tactic_id)],
                "mapping_type": m.mapping_type, "capability_group": m.capability_group,
                "comments": m.comments, "status": m.status,
                "references": [{"reference": r.reference, "is_http_url": r.is_http_url}
                               for r in sorted(m.references.all(), key=lambda r: r.id)]})
        return out

    def get_attack_note(self, v):
        return "empty 'attack' = not mapped by PKEV, NOT 'no technique applies'"


# ------------------------------------------------------------------ techniques --------------------------
class TechniqueListSerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="api-technique-detail", lookup_field="technique_id")
    parent_technique = serializers.PrimaryKeyRelatedField(read_only=True)
    tactics = serializers.SerializerMethodField()
    n_vulnerabilities = serializers.IntegerField(read_only=True)

    class Meta:
        model = AttackTechnique
        fields = ["url", "technique_id", "name", "is_subtechnique", "parent_technique", "status", "tactics",
                  "n_vulnerabilities"]

    def get_tactics(self, t):
        return [x.shortname for x in sorted(t.tactics.all(), key=lambda x: x.tactic_id)]


class TechniqueDetailSerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="api-technique-detail", lookup_field="technique_id")
    parent_technique = serializers.SerializerMethodField()
    subtechniques = serializers.SerializerMethodField()
    tactics = serializers.SerializerMethodField()
    mappings = serializers.SerializerMethodField()

    class Meta:
        model = AttackTechnique
        fields = ["url", "technique_id", "stix_id", "name", "is_subtechnique", "parent_technique", "subtechniques",
                  "status", "created", "modified", "description", "tactics", "mappings"]

    def get_parent_technique(self, t):
        p = t.parent_technique
        return None if p is None else {"technique_id": p.technique_id, "name": p.name}

    def get_subtechniques(self, t):
        return [{"technique_id": s.technique_id, "name": s.name} for s in t.subtechniques.all()]

    def get_tactics(self, t):
        return [{"tactic_id": x.tactic_id, "shortname": x.shortname, "name": x.name}
                for x in sorted(t.tactics.all(), key=lambda x: x.tactic_id)]

    def get_mappings(self, t):
        return [{"mapping_id": m.mapping_id, "cve_id": m.cve_id, "mapping_type": m.mapping_type}
                for m in t.mappings.all()]

    def to_representation(self, t):
        d = super().to_representation(t)
        d["created"], d["modified"] = iso(t.created), iso(t.modified)
        return d


# ------------------------------------------------------------------ tactics, CWE -------------------------
class TacticSerializer(serializers.ModelSerializer):
    n_techniques = serializers.IntegerField(read_only=True)

    class Meta:
        model = AttackTactic
        fields = ["tactic_id", "shortname", "name", "n_techniques"]


class CweSerializer(serializers.ModelSerializer):
    n_kev_vulnerabilities = serializers.IntegerField(read_only=True)
    n_nvd_records = serializers.IntegerField(read_only=True)

    class Meta:
        model = Cwe
        fields = ["cwe_id", "is_informative", "n_kev_vulnerabilities", "n_nvd_records"]
