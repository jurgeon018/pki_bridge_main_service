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
    name = models.CharField(max_length=255, db_index=True)
    contacts = models.CharField(max_length=255, blank=True, null=True)
    last_scan = models.OneToOneField(to='pki_bridge.HostScan', on_delete=models.SET_NULL, null=True, blank=True, related_name='last_host')
    days_to_expire = models.PositiveIntegerField(default=30)

    def __str__(self):
        return f'{self.name}'

    class Meta:
        verbose_name = "Host"
        verbose_name_plural = "Hosts"
        ordering = ['id', ]


class CertificateRequestScan(TimeMixin):
    certificate_request = models.ForeignKey(to='pki_bridge.CertificateRequest', on_delete=models.SET_NULL, null=True, blank=True, related_name='scans')
    error_message = models.TextField(blank=True, null=True)

    def __str__(self):
        return f'{self.id}, {self.certificate_request}'

    class Meta:
        verbose_name = "Certificate request scan"
        verbose_name_plural = "Certificate request scans"


class HostScan(TimeMixin):
    certificate = models.ForeignKey(to='pki_bridge.Certificate', on_delete=models.SET_NULL, null=True, blank=True)
    host = models.ForeignKey(to="pki_bridge.Host", on_delete=models.SET_NULL, blank=True, null=True, related_name='scans')
    port = models.IntegerField(blank=True, null=True)
    error_message = models.TextField(blank=True, null=True)

    def __str__(self):
        return f'{self.id}, {self.host}'

    class Meta:
        verbose_name = "Host scan"
        verbose_name_plural = "Hosts scans"
