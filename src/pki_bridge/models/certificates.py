from django.db import models
from pki_bridge.models.mixins import TimeMixin, ActiveMixin, AuthorMixin


class Template(TimeMixin, ActiveMixin, AuthorMixin):
    name = models.CharField(unique=True, max_length=255)
    description = models.TextField()

    def save(self, *args, **kwargs):
        if not self.description:
            self.description = self.name
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.name}'

    class Meta:
        verbose_name = 'Template'
        verbose_name_plural = 'Templates'


class CertificateRequest(TimeMixin, AuthorMixin):
    email = models.CharField(max_length=255)
    csr = models.TextField()
    certificate = models.TextField()
    template = models.TextField()
    domain = models.TextField()


    def __str__(self):
        return f'{self.email}'

    class Meta:
        verbose_name = "CertificateRequest"
        verbose_name_plural = "CertificateRequests"


class Note(TimeMixin, AuthorMixin):
    certificate_request = models.ForeignKey(to='pki_bridge.CertificateRequest', on_delete=models.SET_NULL, null=True, blank=True)
    text = models.TextField()

    def __str__(self):
        return f'{self.text}'

    class Meta:
        verbose_name = 'Note'
        verbose_name_plural = 'Notes'

