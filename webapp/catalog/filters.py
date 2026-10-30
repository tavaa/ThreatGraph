"""Query-string filters for /api/vulnerabilities/ and /api/techniques/ (django-filter).
A wrong value (e.g. ?ransomware_use=maybe, ?date_added_after=yesterday) gives HTTP 400, never a silent empty list."""
import django_filters as df
from django import forms

from .models import (AttackTechnique, Cwe, MAPPING_TYPE, RANSOMWARE_USE, SEVERITY, TECHNIQUE_STATUS, Vulnerability,
                     choices)


class StrictBooleanField(forms.Field):
    """true/false/1/0 (any case). Anything else is an ERROR: django-filter's default boolean silently ignores
    unknown values (?has_attack=perhaps would return the unfiltered list)."""

    def clean(self, value):
        if value in (None, ""):
            return None
        v = str(value).strip().lower()
        if v in ("true", "1"):
            return True
        if v in ("false", "0"):
            return False
        raise forms.ValidationError("Enter true or false.")


class StrictBooleanFilter(df.Filter):
    field_class = StrictBooleanField


class VulnerabilityFilter(df.FilterSet):
    vendor_project = df.CharFilter(lookup_expr="icontains")
    product = df.CharFilter(lookup_expr="icontains")
    ransomware_use = df.ChoiceFilter(choices=choices(RANSOMWARE_USE))
    date_added_after = df.DateFilter(field_name="date_added", lookup_expr="gte")
    date_added_before = df.DateFilter(field_name="date_added", lookup_expr="lte")
    cwe = df.CharFilter(field_name="cwes__cwe_id", help_text="CWE assigned by KEV, e.g. CWE-79")
    technique = df.CharFilter(field_name="mappings__technique__technique_id", distinct=True,
                              help_text="ATT&CK technique id mapped by PKEV, e.g. T1190")
    tactic = df.CharFilter(field_name="mappings__technique__tactics__shortname", distinct=True,
                           help_text="ATT&CK tactic shortname, e.g. initial-access")
    mapping_type = df.ChoiceFilter(field_name="mappings__mapping_type", choices=choices(MAPPING_TYPE), distinct=True)
    severity = df.ChoiceFilter(field_name="nvd__cvss_v31_severity", choices=choices(SEVERITY))
    min_cvss = df.NumberFilter(field_name="nvd__cvss_v31_score", lookup_expr="gte")
    has_attack = StrictBooleanFilter(method="filter_has_attack", help_text="true = at least one PKEV mapping")

    class Meta:
        model = Vulnerability
        fields = []

    def filter_has_attack(self, qs, name, value):
        return qs.filter(n_mappings__gt=0) if value else qs.filter(n_mappings=0)

    @property
    def qs(self):
        return super().qs.distinct()


class TechniqueFilter(df.FilterSet):
    status = df.ChoiceFilter(choices=choices(TECHNIQUE_STATUS))
    is_subtechnique = StrictBooleanFilter()
    tactic = df.CharFilter(field_name="tactics__shortname", distinct=True)
    name = df.CharFilter(lookup_expr="icontains")
    has_vulnerabilities = StrictBooleanFilter(method="filter_has_vulns", help_text="true = used by at least one PKEV mapping")

    class Meta:
        model = AttackTechnique
        fields = []

    def filter_has_vulns(self, qs, name, value):
        return qs.filter(n_vulnerabilities__gt=0) if value else qs.filter(n_vulnerabilities=0)


class CweFilter(df.FilterSet):
    is_informative = StrictBooleanFilter()

    class Meta:
        model = Cwe
        fields = []
