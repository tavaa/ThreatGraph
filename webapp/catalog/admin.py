from django.contrib import admin

from .models import (AttackTactic, AttackTechnique, AttackTechniqueTactic, Cwe, KevCwe, NvdCveCwe, NvdRecord,
                     PkevMapping, PkevMappingReference, Vulnerability)

# Read-mostly catalogue: the data comes from data/clean/ (management command load_clean_data).
# list_display / list_filter / search_fields as in the insurance example; raw_id_fields avoids huge <select> boxes.


class MappingInline(admin.TabularInline):
    model = PkevMapping
    extra = 0
    raw_id_fields = ("technique",)


class VulnerabilityAdmin(admin.ModelAdmin):
    model = Vulnerability
    list_display = ("cve_id", "vendor_project", "product", "date_added", "ransomware_use", "due_before_added")
    list_filter = ("ransomware_use", "due_before_added", "date_added")
    search_fields = ("cve_id", "vendor_project", "product", "vulnerability_name")
    inlines = [MappingInline]


class CweAdmin(admin.ModelAdmin):
    model = Cwe
    list_display = ("cwe_id", "is_informative")
    list_filter = ("is_informative",)
    search_fields = ("cwe_id",)


class KevCweAdmin(admin.ModelAdmin):
    model = KevCwe
    list_display = ("cve", "cwe")
    raw_id_fields = ("cve", "cwe")


class NvdRecordAdmin(admin.ModelAdmin):
    model = NvdRecord
    list_display = ("cve", "vuln_status", "cvss_v31_score", "cvss_v31_severity", "cvss_v31_type", "published")
    list_filter = ("vuln_status", "cvss_v31_severity", "cvss_v31_type")
    search_fields = ("cve__cve_id", "description_en")
    raw_id_fields = ("cve",)


class NvdCveCweAdmin(admin.ModelAdmin):
    model = NvdCveCwe
    list_display = ("cve", "cwe", "source", "type")
    list_filter = ("type",)
    raw_id_fields = ("cve", "cwe")


class AttackTacticAdmin(admin.ModelAdmin):
    model = AttackTactic
    list_display = ("tactic_id", "shortname", "name")


class AttackTechniqueAdmin(admin.ModelAdmin):
    model = AttackTechnique
    list_display = ("technique_id", "name", "is_subtechnique", "status", "modified")
    list_filter = ("status", "is_subtechnique")
    search_fields = ("technique_id", "name")
    raw_id_fields = ("parent_technique",)


class AttackTechniqueTacticAdmin(admin.ModelAdmin):
    model = AttackTechniqueTactic
    list_display = ("technique", "tactic")
    raw_id_fields = ("technique", "tactic")


class PkevMappingAdmin(admin.ModelAdmin):
    model = PkevMapping
    list_display = ("mapping_id", "cve", "technique", "mapping_type", "capability_group")
    list_filter = ("mapping_type", "capability_group")
    search_fields = ("cve__cve_id", "technique__technique_id", "technique__name")
    raw_id_fields = ("cve", "technique")


class PkevMappingReferenceAdmin(admin.ModelAdmin):
    model = PkevMappingReference
    list_display = ("mapping", "reference", "is_http_url")
    list_filter = ("is_http_url",)
    raw_id_fields = ("mapping",)


admin.site.register(Vulnerability, VulnerabilityAdmin)
admin.site.register(Cwe, CweAdmin)
admin.site.register(KevCwe, KevCweAdmin)
admin.site.register(NvdRecord, NvdRecordAdmin)
admin.site.register(NvdCveCwe, NvdCveCweAdmin)
admin.site.register(AttackTactic, AttackTacticAdmin)
admin.site.register(AttackTechnique, AttackTechniqueAdmin)
admin.site.register(AttackTechniqueTactic, AttackTechniqueTacticAdmin)
admin.site.register(PkevMapping, PkevMappingAdmin)
admin.site.register(PkevMappingReference, PkevMappingReferenceAdmin)
