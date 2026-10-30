"""Minimal views (Phase 3). The real REST API / JSON-LD comes in Phase 4."""
from django.http import Http404, JsonResponse

from catalog.models import (AttackTactic, AttackTechnique, AttackTechniqueTactic, Cwe, KevCwe, NvdCveCwe, NvdRecord,
                            PkevMapping, PkevMappingReference, Vulnerability)

MODELS = (Vulnerability, Cwe, KevCwe, NvdRecord, NvdCveCwe, AttackTactic, AttackTechnique, AttackTechniqueTactic,
          PkevMapping, PkevMappingReference)


def stats(request):
    """Row count of every table."""
    return JsonResponse({m.__name__: m.objects.count() for m in MODELS})


def vulnerability(request, cve_id):
    """One CVE seen through the four sources: KEV + NVD + CWE + ATT&CK (via PKEV)."""
    try:
        v = Vulnerability.objects.select_related("nvd").get(pk=cve_id)
    except Vulnerability.DoesNotExist:
        raise Http404(f"{cve_id} is not in KEV")
    nvd = getattr(v, "nvd", None)
    return JsonResponse({
        "cve_id": v.cve_id,
        "kev": {"vendor": v.vendor_project, "product": v.product, "name": v.vulnerability_name,
                "date_added": v.date_added.isoformat(), "ransomware_use": v.ransomware_use,
                "cwes": [c.cwe_id for c in v.cwes.all()]},
        "nvd": None if nvd is None else {
            "status": nvd.vuln_status, "published": nvd.published.isoformat(),
            "cvss_v31": {"score": nvd.cvss_v31_score, "severity": nvd.cvss_v31_severity, "type": nvd.cvss_v31_type},
            "cwes": [{"cwe": x.cwe_id, "source": x.source, "type": x.type} for x in nvd.nvdcvecwe_set.all()]},
        "attack": [{"technique": m.technique_id, "name": m.technique.name, "mapping_type": m.mapping_type,
                    "tactics": [t.shortname for t in m.technique.tactics.all()]}
                   for m in v.mappings.select_related("technique").all()],
        "pkev_note": "empty 'attack' = not mapped by PKEV, NOT 'no technique applies'",
    })
