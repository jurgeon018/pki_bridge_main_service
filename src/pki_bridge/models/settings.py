from django.db import models
from django.conf import settings
from solo.models import SingletonModel
from django.core.exceptions import ValidationError


BASE_DIR = settings.BASE_DIR


class EmailSettingsFieldsMixin(models.Model):
    email_host = models.CharField(
        blank=True, null=True,
        max_length=256,
        default=settings.EMAIL_HOST,
    )
    email_port = models.SmallIntegerField(
        blank=True, null=True,
        default=settings.EMAIL_PORT,
    )
    default_from_email = models.CharField(
        blank=True, null=True,
        max_length=256,
        default=settings.DEFAULT_FROM_EMAIL,
    )
    email_host_user = models.CharField(
        blank=True, null=True,
        max_length=256,
    )
    email_host_password = models.CharField(
        blank=True, null=True,
        max_length=256,
    )
    email_use_tls = models.BooleanField(
        default=settings.EMAIL_USE_TLS,
    )
    email_use_ssl = models.BooleanField(
        default=settings.EMAIL_USE_SSL,
    )
    fail_silently = models.BooleanField(
        default=False,
        help_text="Throw error when mail sending wasnt successful"
    )
    timeout = models.SmallIntegerField(
        blank=True, null=True,
        help_text="Timeout in seconds"
    )

    def update_mail_settings(self):
        self.email_host = settings.EMAIL_HOST
        self.email_port = settings.EMAIL_PORT
        self.default_from_email = settings.DEFAULT_FROM_EMAIL
        self.email_host_user = settings.EMAIL_HOST_USER
        self.email_host_password = settings.EMAIL_HOST_PASSWORD
        self.email_use_tls = settings.EMAIL_USE_TLS
        self.email_use_ssl = settings.EMAIL_USE_SSL

    def clean(self):
        if self.email_use_tls and self.email_use_ssl:
            raise ValidationError(
                ("\"Use TLS\" and \"Use SSL\" are mutually exclusive, "
                    "so only set one of those settings to True."))

    class Meta:
        abstract = True


class PkiFieldsMixin(models.Model):
    scan_timeout = models.IntegerField(default=2)
    update_templates_from_ca = models.BooleanField(default=False)
    ldap_username = models.CharField(max_length=255, blank=True, null=True)
    ldap_password = models.CharField(max_length=255, blank=True, null=True)
    allow_use_file_as_ldap_results = models.BooleanField(blank=True, null=True)

    allowed_requests = models.PositiveIntegerField(
        blank=True, null=True,
        help_text='per {reset_period} hours for one IP-address',
    )
    reset_period = models.PositiveIntegerField(blank=True, null=True)

    ca = models.TextField()
    intermediary = models.TextField()
    chain = models.TextField()

    def update_from_config(self):
        self.update_templates_from_ca = settings.UPDATE_TEMPLATES_FROM_CA
        self.ldap_username = settings.LDAP_USERNAME
        self.ldap_password = settings.LDAP_PASSWORD
        self.scan_timeout = settings.SCAN_TIMEOUT
        self.allowed_requests = settings.ALLOWED_REQUESTS
        self.reset_period = settings.RESET_PERIOD
        self.allow_use_file_as_ldap_results = settings.ALLOW_USE_FILE_AS_LDAP_RESULTS
        with open(BASE_DIR / 'fixtures' / 'key.key') as f:
            self.ca = f.read()
        with open(BASE_DIR / 'fixtures' / 'cer.cer') as f:
            self.intermediary = f.read()
        with open(BASE_DIR / 'fixtures' / 'chain.cer') as f:
            self.chain = f.read()

    class Meta:
        abstract = True


class ProjectSettings(
    PkiFieldsMixin,
    EmailSettingsFieldsMixin,
    SingletonModel,
        ):
    def update_settings(self):
        self.update_from_config()
        self.update_mail_settings()
        self.save()

    def __str__(self):
        return f'{self.id}'

    class Meta:
        verbose_name = 'ProjectSettings'
        verbose_name_plural = 'ProjectSettings'
