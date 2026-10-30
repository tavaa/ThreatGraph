"""REST API, read-only (Phase 4). Every endpoint answers GET only; POST/PUT/PATCH/DELETE -> 405.

Content negotiation: application/json (default), application/ld+json (?format=jsonld), browsable HTML.
"""
import json

from django.db.models import Count, Prefetch
from rest_framework import filters, viewsets
from rest_framework.decorators import api_view, renderer_classes
from rest_framework.renderers import BrowsableAPIRenderer, JSONRenderer
from rest_framework.response import Response

from threatgraph import config, jsonld

from . import serializers as S
from .filters import CweFilter, TechniqueFilter, VulnerabilityFilter
from .models import (AttackTactic, AttackTechnique, Cwe, KevCwe, NvdCveCwe, NvdRecord, PkevMapping,
                     PkevMappingReference, Vulnerability, AttackTechniqueTactic)
from .renderers import JsonLdRenderer
from django_filters.rest_framework import DjangoFilterBackend

PROV = jsonld.prov_iris(config.load_sources())          # {'kev': iri, 'nvd': iri, 'attack': iri, 'pkev': iri}


def _is_ld(request):
    r = getattr(request, "accepted_renderer", None)
    return r is not None and r.format == "jsonld"


class JsonLdMixin:
    """If the client asked for JSON-LD, convert the REST dictionaries with ``node_builder``."""
    node_builder = None

    def retrieve(self, request, *args, **kwargs):
        resp = super().retrieve(request, *args, **kwargs)
        if _is_ld(request):
            resp.data = jsonld.document(type(self).node_builder(resp.data, PROV))
        return resp

    def list(self, request, *args, **kwargs):
        resp = super().list(request, *args, **kwargs)
        if _is_ld(request) and isinstance(resp.data, dict) and "results" in resp.data:
            d = resp.data
            resp.data = jsonld.graph_document(
                [type(self).node_builder(x, PROV) for x in d["results"]],
                totalItems=d["count"], nextPage=d["next"], previousPage=d["previous"])
        return resp


class VulnerabilityViewSet(JsonLdMixin, viewsets.ReadOnlyModelViewSet):
    """KEV vulnerabilities. Filters: vendor_project, product, ransomware_use, date_added_after/before, cwe,
    technique, tactic, mapping_type, severity, min_cvss, has_attack. ?search= ?ordering= ?page= ?page_size="""
    lookup_field = "cve_id"
    node_builder = staticmethod(jsonld.vulnerability_node)
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = VulnerabilityFilter
    search_fields = ["cve_id", "vendor_project", "product", "vulnerability_name"]
    ordering_fields = {"cve_id": "cve_id", "date_added": "date_added", "cvss": "nvd__cvss_v31_score",
                       "n_mappings": "n_mappings"}
    ordering = ["cve_id"]

    def get_queryset(self):
        qs = Vulnerability.objects.select_related("nvd").annotate(n_mappings=Count("mappings", distinct=True))
        if self.action == "retrieve":
            qs = qs.prefetch_related(
                "cwes", "nvd__nvdcvecwe_set__cwe",
                Prefetch("mappings", queryset=PkevMapping.objects.select_related("technique")
                         .prefetch_related("technique__tactics", "references")))
        return qs

    def get_serializer_class(self):
        return S.VulnerabilityDetailSerializer if self.action == "retrieve" else S.VulnerabilityListSerializer


class TechniqueViewSet(JsonLdMixin, viewsets.ReadOnlyModelViewSet):
    """ATT&CK techniques and sub-techniques. Filters: status, is_subtechnique, tactic, name, has_vulnerabilities."""
    lookup_field = "technique_id"
    lookup_value_regex = r"T\d{4}(\.\d{3})?"            # the dot of T1059.001 must not be read as a format suffix
    node_builder = staticmethod(jsonld.technique_node)
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = TechniqueFilter
    search_fields = ["technique_id", "name"]
    ordering_fields = ["technique_id", "name", "n_vulnerabilities"]
    ordering = ["technique_id"]

    def get_queryset(self):
        qs = AttackTechnique.objects.annotate(n_vulnerabilities=Count("mappings__cve", distinct=True))
        qs = qs.prefetch_related("tactics")
        if self.action == "retrieve":
            qs = qs.select_related("parent_technique").prefetch_related("subtechniques", "mappings")
        return qs

    def get_serializer_class(self):
        return S.TechniqueDetailSerializer if self.action == "retrieve" else S.TechniqueListSerializer


class TacticViewSet(viewsets.ReadOnlyModelViewSet):
    lookup_field = "tactic_id"
    serializer_class = S.TacticSerializer
    pagination_class = None                              # only 14 rows
    queryset = AttackTactic.objects.annotate(n_techniques=Count("techniques", distinct=True)).order_by("tactic_id")


class CweViewSet(viewsets.ReadOnlyModelViewSet):
    lookup_field = "cwe_id"
    serializer_class = S.CweSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_class = CweFilter
    search_fields = ["cwe_id"]
    queryset = (Cwe.objects.annotate(n_kev_vulnerabilities=Count("kev_vulnerabilities", distinct=True),
                                     n_nvd_records=Count("nvd_records", distinct=True)).order_by("cwe_id"))


# ------------------------------------------------------------------ dataset description + context ----
@api_view(["GET"])
@renderer_classes([JsonLdRenderer, JSONRenderer, BrowsableAPIRenderer])
def dataset(request):
    """DCAT description of the integrated dataset + PROV links to the four pinned sources (FAIR F2, R1.2)."""
    manifest = json.loads((config.CLEAN_DIR / "manifest.json").read_text())
    counts = {"kev_vulnerability": Vulnerability.objects.count(), "kev_cwe": KevCwe.objects.count(),
              "nvd_cve": NvdRecord.objects.count(), "nvd_cve_cwe": NvdCveCwe.objects.count(),
              "attack_tactic": AttackTactic.objects.count(), "attack_technique": AttackTechnique.objects.count(),
              "attack_technique_tactic": AttackTechniqueTactic.objects.count(),
              "pkev_mapping": PkevMapping.objects.count(), "pkev_mapping_reference": PkevMappingReference.objects.count()}
    node = jsonld.dataset_node(request.build_absolute_uri("/"), config.load_sources(), manifest, counts)
    return Response(jsonld.document(node))


@api_view(["GET"])
@renderer_classes([JsonLdRenderer, JSONRenderer])
def context(request):
    """The @context alone, so that clients can cache it instead of receiving it in every response."""
    return Response({"@context": jsonld.CONTEXT})
