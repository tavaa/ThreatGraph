"""ThreatGraph-LD -- relational model (Phase 3).

One Django model per table of the clean layer (data/clean/*.csv) plus ONE derived
table, ``Cwe`` (so 9 + 1 = 10 models). Same column names as the CSV files, so loading is a 1:1 copy.

Sources (colours in the UML):  KEV | NVD | ATT&CK | PKEV | derived

Design decisions [PROPOSAL]:
  * Natural keys are kept as primary keys where they are single and stable (cve_id, technique_id,
    tactic_id, cwe_id). Link tables get a surrogate ``id`` + a UniqueConstraint on the natural key.
  * Many-to-many relations use an explicit ``through`` model = UML "association class".
    PkevMapping is the important one: it carries mapping_type, comments, ... (attributes of the relation).
  * ``Cwe`` is derived from the two CWE link tables. ``is_informative`` depends only on cwe_id, so it
    lives on Cwe (third normal form) instead of being repeated on every link row.
  * NULL = "the source did not say" (never imputed). Nullable fields have null=True.
  * Timestamps are UTC (USE_TZ=True). Mutable raw files are NOT referenced here: provenance of the
    load is in data/clean/manifest.json (Phase 5 will add snapshot records).
"""
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models

RANSOMWARE_USE = ("known", "unknown")
SEVERITY = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
METRIC_TYPE = ("Primary", "Secondary")
TECHNIQUE_STATUS = ("active", "revoked", "deprecated")
MAPPING_TYPE = ("exploitation_technique", "primary_impact", "secondary_impact")
VULN_STATUS = ("Received", "Awaiting Analysis", "Undergoing Analysis", "Analyzed", "Modified",
               "Deferred", "Rejected", "Reanalysis")


def choices(values):
    return [(v, v) for v in values]


cve_validator = RegexValidator(r"^CVE-\d{4}-\d{4,}$", "Expected CVE-YYYY-NNNN")
technique_validator = RegexValidator(r"^T\d{4}(\.\d{3})?$", "Expected T#### or T####.###")
score_validators = [MinValueValidator(0), MaxValueValidator(10)]


# ------------------------------------------------------------------ KEV ---------------
class Vulnerability(models.Model):
    """A CVE listed in CISA KEV (table kev_vulnerability). This is the scope of the project."""
    cve_id = models.CharField(max_length=20, primary_key=True, validators=[cve_validator])
    vendor_project = models.CharField(max_length=100)
    product = models.CharField(max_length=200)
    vulnerability_name = models.CharField(max_length=300)
    date_added = models.DateField()
    due_date = models.DateField()
    short_description = models.TextField()
    required_action = models.TextField()
    ransomware_use = models.CharField(max_length=7, choices=choices(RANSOMWARE_USE),
                                      help_text="'unknown' = no evidence recorded, NOT 'false'")
    notes = models.TextField()
    due_before_added = models.BooleanField(help_text="Source anomaly kept as is: dueDate < dateAdded")
    src_row = models.PositiveIntegerField(help_text="Position in the raw KEV file")
    cwes = models.ManyToManyField("Cwe", through="KevCwe", related_name="kev_vulnerabilities")
    techniques = models.ManyToManyField("AttackTechnique", through="PkevMapping", related_name="vulnerabilities")

    class Meta:
        ordering = ["cve_id"]
        verbose_name_plural = "vulnerabilities"

    def __str__(self):
        return f"{self.cve_id} ({self.vendor_project} {self.product})"


# ------------------------------------------------------------------ CWE (derived) ------
class Cwe(models.Model):
    """Weakness category. Derived: distinct cwe_id of kev_cwe and nvd_cve_cwe (the CWE catalogue itself
    is not a source of this project, so no name/description)."""
    cwe_id = models.CharField(max_length=30, primary_key=True)
    is_informative = models.BooleanField(help_text="False for NVD-CWE-noinfo / NVD-CWE-Other")

    class Meta:
        ordering = ["cwe_id"]

    def __str__(self):
        return self.cwe_id


class KevCwe(models.Model):
    """Association: KEV vulnerability <-> CWE (table kev_cwe)."""
    cve = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    cwe = models.ForeignKey(Cwe, on_delete=models.CASCADE)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["cve", "cwe"], name="uniq_kevcwe")]

    def __str__(self):
        return f"{self.cve_id} - {self.cwe_id}"


# ------------------------------------------------------------------ NVD ----------------
class NvdRecord(models.Model):
    """NVD description of the same CVE (table nvd_cve). One-to-one with Vulnerability."""
    cve = models.OneToOneField(Vulnerability, primary_key=True, on_delete=models.CASCADE, related_name="nvd")
    source_identifier = models.CharField(max_length=100)
    published = models.DateTimeField()
    last_modified = models.DateTimeField()
    vuln_status = models.CharField(max_length=30, choices=choices(VULN_STATUS))
    description_en = models.TextField()
    # CVSS v3.1 only (assumption N2). All five NULL together when the CVE has no v3.1.
    cvss_v31_score = models.FloatField(null=True, blank=True, validators=score_validators)
    cvss_v31_severity = models.CharField(max_length=8, null=True, blank=True, choices=choices(SEVERITY))
    cvss_v31_vector = models.CharField(max_length=100, null=True, blank=True)
    cvss_v31_source = models.CharField(max_length=100, null=True, blank=True)
    cvss_v31_type = models.CharField(max_length=9, null=True, blank=True, choices=choices(METRIC_TYPE))
    cvss_v2_score = models.FloatField(null=True, blank=True, validators=score_validators)
    n_references = models.PositiveIntegerField()
    cwes = models.ManyToManyField(Cwe, through="NvdCveCwe", related_name="nvd_records")

    class Meta:
        ordering = ["cve_id"]

    def __str__(self):
        return f"NVD {self.cve_id} [{self.vuln_status}]"


class NvdCveCwe(models.Model):
    """Association: NVD record <-> CWE, with who said it (table nvd_cve_cwe)."""
    cve = models.ForeignKey(NvdRecord, on_delete=models.CASCADE)
    cwe = models.ForeignKey(Cwe, on_delete=models.CASCADE)
    source = models.CharField(max_length=100, help_text="Who assigned the CWE (NVD or a CNA)")
    type = models.CharField(max_length=9, choices=choices(METRIC_TYPE))

    class Meta:
        constraints = [models.UniqueConstraint(fields=["cve", "cwe", "source"], name="uniq_nvdcvecwe")]

    def __str__(self):
        return f"{self.cve_id} - {self.cwe_id} ({self.source})"


# ------------------------------------------------------------------ ATT&CK -------------
class AttackTactic(models.Model):
    """ATT&CK tactic = the attacker's goal (table attack_tactic)."""
    tactic_id = models.CharField(max_length=10, primary_key=True)
    shortname = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=100)
    stix_id = models.CharField(max_length=80, unique=True)

    def __str__(self):
        return f"{self.tactic_id} {self.name}"


class AttackTechnique(models.Model):
    """ATT&CK technique or sub-technique (table attack_technique)."""
    technique_id = models.CharField(max_length=10, primary_key=True, validators=[technique_validator])
    stix_id = models.CharField(max_length=80, unique=True)
    name = models.CharField(max_length=200)
    is_subtechnique = models.BooleanField()
    parent_technique = models.ForeignKey("self", null=True, blank=True, on_delete=models.PROTECT,
                                         related_name="subtechniques")
    status = models.CharField(max_length=10, choices=choices(TECHNIQUE_STATUS),
                              help_text="Filter status='active' for current use")
    created = models.DateTimeField()
    modified = models.DateTimeField()
    description = models.TextField(null=True, blank=True)
    tactics = models.ManyToManyField(AttackTactic, through="AttackTechniqueTactic", related_name="techniques")

    class Meta:
        ordering = ["technique_id"]

    def __str__(self):
        return f"{self.technique_id} {self.name}"


class AttackTechniqueTactic(models.Model):
    """Association: technique <-> tactic (table attack_technique_tactic)."""
    technique = models.ForeignKey(AttackTechnique, on_delete=models.CASCADE)
    tactic = models.ForeignKey(AttackTactic, on_delete=models.CASCADE)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["technique", "tactic"], name="uniq_techtactic")]

    def __str__(self):
        return f"{self.technique_id} - {self.tactic_id}"


# ------------------------------------------------------------------ PKEV ---------------
class PkevMapping(models.Model):
    """Association CLASS: expert statement 'this KEV CVE is exploited with / has impact via this technique'
    (table pkev_mapping). Absence of a row = 'not mapped by PKEV', NOT 'no technique applies'."""
    mapping_id = models.PositiveIntegerField(primary_key=True, help_text="1-based position in the PKEV file")
    cve = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name="mappings")
    technique = models.ForeignKey(AttackTechnique, on_delete=models.PROTECT, related_name="mappings")
    mapping_type = models.CharField(max_length=25, choices=choices(MAPPING_TYPE))
    capability_group = models.CharField(max_length=100)
    comments = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=20)

    class Meta:
        ordering = ["mapping_id"]
        constraints = [models.UniqueConstraint(fields=["cve", "technique", "mapping_type"], name="uniq_pkevmapping")]

    def __str__(self):
        return f"{self.cve_id} -> {self.technique_id} ({self.mapping_type})"


class PkevMappingReference(models.Model):
    """Evidence attached to a mapping (table pkev_mapping_reference). The source field is dirty:
    strings that are not a single http(s) URL are kept verbatim with is_http_url = False."""
    mapping = models.ForeignKey(PkevMapping, on_delete=models.CASCADE, related_name="references")
    reference = models.TextField()
    is_http_url = models.BooleanField()

    class Meta:
        constraints = [models.UniqueConstraint(fields=["mapping", "reference"], name="uniq_pkevref")]

    def __str__(self):
        return f"{self.mapping_id}: {self.reference[:60]}"
