from django.db import models
from pki_bridge.models.mixins import TimeMixin, ActiveMixin, AuthorMixin


class Network(TimeMixin, ActiveMixin, AuthorMixin):
    name = models.CharField(max_length=255, blank=True, null=True)
    ip = models.CharField(max_length=255, blank=True, null=True)
    mask = models.CharField(max_length=255, blank=True, null=True)
    vlan_id = models.CharField(max_length=255, blank=True, null=True)
    contacts = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f'{self.ip}/{self.mask}'

    class Meta:
        unique_together = [
            'ip',
            'mask',
        ]
        verbose_name = "Network"
        verbose_name_plural = "Network"


class Host(TimeMixin, ActiveMixin, AuthorMixin):
    network = models.ForeignKey(to='pki_bridge.Network', on_delete=models.SET_NULL, blank=True, null=True, related_name="hosts")
    host = models.CharField(max_length=255, unique=True, db_index=True)
    contacts = models.CharField(max_length=255, blank=True, null=True)
    last_scan = models.OneToOneField(to='pki_bridge.Scan', on_delete=models.SET_NULL, null=True, blank=True, related_name='last_host')

    def __str__(self):
        return f'{self.host}'

    class Meta:
        verbose_name = "Host"
        verbose_name_plural = "Hosts"


class Scan(TimeMixin):
    host = models.ForeignKey(to="pki_bridge.Host", on_delete=models.SET_NULL, blank=True, null=True, related_name='scans')
    hostname = models.TextField(blank=True, null=True)
    result = models.TextField(null=True, blank=True)
    pem = models.TextField(null=True, blank=True)
    cert = models.TextField(null=True, blank=True)
    issued_to = models.TextField(blank=True, null=True)
    issued_o = models.TextField(blank=True, null=True)
    issuer_c = models.TextField(blank=True, null=True)
    issuer_o = models.TextField(blank=True, null=True)
    issuer_ou = models.TextField(blank=True, null=True)
    issuer_cn = models.TextField(blank=True, null=True)
    cert_sn = models.TextField(blank=True, null=True)
    cert_sha1 = models.TextField(blank=True, null=True)
    cert_alg = models.TextField(blank=True, null=True)
    cert_ver = models.IntegerField()
    cert_sans = models.TextField(blank=True, null=True)
    cert_exp = models.BooleanField()
    valid_from = models.DateField()
    valid_till = models.DateField()
    validity_days = models.IntegerField()
    days_left = models.IntegerField()
    valid_days_to_expire = models.IntegerField()
    tcp_port = models.IntegerField()

    def __str__(self):
        return f'{self.id}, {self.host}'

    class Meta:
        verbose_name = "Scan"
        verbose_name_plural = "Scans"

