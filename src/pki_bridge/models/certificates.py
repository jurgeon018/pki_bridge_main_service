from datetime import datetime

from django.db import models
from django.utils import timezone
from pki_bridge.core.converter import Converter
from pki_bridge.core.utils import make_timezone_aware
from pki_bridge.models.mixins import ActiveMixin
from pki_bridge.models.mixins import AuthorMixin
from pki_bridge.models.mixins import TimeMixin
from pki_bridge.models.settings import AllowedCN


class Template(TimeMixin, ActiveMixin, AuthorMixin):
    name = models.CharField(unique=True, max_length=255)
    description = models.TextField()

    def save(self, *args, **kwargs):
        if not self.description:
            self.description = self.name
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.name}"

    class Meta:
        verbose_name = "Template"
        verbose_name_plural = "Templates"


class Requester(TimeMixin, AuthorMixin):
    email = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.email}"

    class Meta:
        verbose_name = "Requester"
        verbose_name_plural = "Requesters"


class Note(TimeMixin, AuthorMixin):
    certificate_request = models.ForeignKey(to="pki_bridge.CertificateRequest", on_delete=models.SET_NULL, null=True, blank=True)
    text = models.TextField()

    def __str__(self):
        return f"{self.text}"

    class Meta:
        verbose_name = "Note"
        verbose_name_plural = "Notes"


class CertificateRequest(TimeMixin, AuthorMixin):
    requester = models.ForeignKey(to="pki_bridge.Requester", on_delete=models.SET_NULL, null=True, blank=True)
    template = models.TextField()
    domain = models.TextField()
    SAN = models.TextField()
    csr = models.TextField()
    certificate = models.OneToOneField(to="pki_bridge.Certificate", on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"{self.id}: {self.requester}, {self.created}"

    class Meta:
        ordering = [
            "id",
        ]
        verbose_name = "CertificateRequest"
        verbose_name_plural = "CertificateRequests"


class Certificate(TimeMixin, AuthorMixin):
    pem = models.TextField(null=False, blank=False)

    valid_from = models.DateTimeField(blank=True, null=True)
    valid_till = models.DateTimeField(blank=True, null=True)

    issued_to = models.TextField(blank=True, null=True)
    issuer_ou = models.TextField(blank=True, null=True)
    issuer_cn = models.TextField(blank=True, null=True)
    issued_o = models.TextField(blank=True, null=True)
    issuer_c = models.TextField(blank=True, null=True)
    issuer_o = models.TextField(blank=True, null=True)
    cert_sha1 = models.TextField(blank=True, null=True)
    cert_sans = models.TextField(blank=True, null=True)
    cert_alg = models.TextField(blank=True, null=True)
    cert_ver = models.IntegerField(blank=True, null=True)
    cert_sn = models.TextField(blank=True, null=True)

    cert_info = models.TextField(null=True, blank=True)
    cert_json = models.TextField(null=True, blank=True)

    def populate(self):
        pem = self.pem
        # cryptography_json_cert = Converter(pem, 'pem', 'json').cert
        self.cert_info = Converter(self.pem, "pem", "text").cert
        self.cert_json = Converter(self.pem, "pem", "json").cert

        pyopenssl_cert = Converter(pem, "pem", "pyopenssl_cert").cert
        pyopenssl_json_cert = Converter(pyopenssl_cert, "pyopenssl_cert", "json").cert

        self.issued_to = pyopenssl_json_cert["issued_to"]
        self.issuer_ou = pyopenssl_json_cert["issuer_ou"]
        self.issuer_cn = pyopenssl_json_cert["issuer_cn"]
        self.issued_o = pyopenssl_json_cert["issued_o"]
        self.issuer_c = pyopenssl_json_cert["issuer_c"]
        self.issuer_o = pyopenssl_json_cert["issuer_o"]

        self.cert_sha1 = pyopenssl_json_cert["cert_sha1"]
        self.cert_sans = pyopenssl_json_cert["cert_sans"]
        self.cert_alg = pyopenssl_json_cert["cert_alg"]
        self.cert_ver = pyopenssl_json_cert["cert_ver"]
        self.cert_sn = pyopenssl_json_cert["cert_sn"]

        dt_format = "%Y-%m-%d"
        valid_from = pyopenssl_json_cert["valid_from"]
        valid_till = pyopenssl_json_cert["valid_till"]
        valid_from = datetime.strptime(valid_from, dt_format)
        valid_till = datetime.strptime(valid_till, dt_format)
        valid_from = make_timezone_aware(valid_from)
        valid_till = make_timezone_aware(valid_till)
        self.valid_from = valid_from
        self.valid_till = valid_till

    def save(self, *args, **kwargs):
        if not self.id:
            self.populate()
        old_pem = self.pem
        super().save(*args, **kwargs)
        new_pem = self.pem
        if old_pem != new_pem:
            self.populate()
            super().save(*args, **kwargs)

    @property
    def is_from_different_ca(self):
        allowed_cns = AllowedCN.objects.filter(is_active=True)
        allowed_cns = allowed_cns.values_list("name", flat=True)
        if self.issuer_cn not in allowed_cns:
            from_different_ca = True
        else:
            from_different_ca = False
        return from_different_ca

    @property
    def is_self_signed(self):
        pem = self.pem
        pyopenssl_cert = Converter(pem, "pem", "pyopenssl_cert").cert
        pyopenssl_json_cert = Converter(pyopenssl_cert, "pyopenssl_cert", "json").cert
        self_signed = pyopenssl_json_cert["self_signed"]
        return self_signed

    @property
    def valid_days_to_expire(self):
        return (self.valid_till - timezone.now()).days

    @property
    def validity_days(self):
        return (self.valid_till - self.valid_from).days

    @property
    def is_expired(self):
        try:
            pem = self.pem
            pyopenssl_cert = Converter(pem, "pem", "pyopenssl_cert").cert
            pyopenssl_json_cert = Converter(pyopenssl_cert, "pyopenssl_cert", "json").cert
            expired = pyopenssl_json_cert["cert_exp"]
        except Exception:
            expired = self.days_left <= 0
        return expired

    def __str__(self):
        return f"{self.id}"

    class Meta:
        verbose_name = "Certificate"
        verbose_name_plural = "Certificates"
