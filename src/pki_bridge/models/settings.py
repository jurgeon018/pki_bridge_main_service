from django.db import models
from django.conf import settings
from solo.models import SingletonModel
from django.core.exceptions import ValidationError
from pki_bridge.models.networks import Host
from pki_bridge.models.mixins import ActiveMixin

BASE_DIR = settings.BASE_DIR


class PkiFieldsMixin(models.Model):
    validate_templates = models.BooleanField()
    enable_mail_notifications = models.BooleanField()
    update_templates_from_ca = models.BooleanField()
    allow_use_file_as_ldap_results = models.BooleanField()
    enable_template_rights_validation = models.BooleanField()

    ldap_username = models.CharField(max_length=255)
    ldap_password = models.CharField(max_length=255)

    days_to_expire = models.PositiveIntegerField()
    scan_timeout = models.IntegerField()
    hosts_per_page = models.PositiveIntegerField(blank=True, null=True)
    certificates_per_page = models.PositiveIntegerField(blank=True, null=True)
    reset_period = models.PositiveIntegerField(blank=True, null=True)
    allowed_requests = models.PositiveIntegerField(
        blank=True, null=True,
        help_text='per {reset_period} hours for one IP-address',
    )

    ca = models.TextField()
    intermediary = models.TextField()
    chain = models.TextField()

    scanner_secret_key = models.SlugField()

    @property
    def ports(self):
        return Port.objects.filter(is_active=True).values_list('name', flat=True)

    def update_fields(self):

        self.hosts_per_page = settings.HOSTS_PER_PAGE
        self.certificates_per_page = settings.CERTIFICATES_PER_PAGE
        self.enable_mail_notifications = settings.ENABLE_MAIL_NOTIFICATIONS
        self.validate_templates = settings.VALIDATE_TEMPLATES
        self.update_templates_from_ca = settings.UPDATE_TEMPLATES_FROM_CA
        self.ldap_username = settings.LDAP_USERNAME
        self.ldap_password = settings.LDAP_PASSWORD
        self.scan_timeout = settings.SCAN_TIMEOUT
        self.allowed_requests = settings.ALLOWED_REQUESTS
        self.reset_period = settings.RESET_PERIOD
        self.allow_use_file_as_ldap_results = settings.ALLOW_USE_FILE_AS_LDAP_RESULTS
        self.days_to_expire = settings.DAYS_TO_EXPIRE
        self.scanner_secret_key = settings.SCANNER_SECRET_KEY
        self.enable_template_rights_validation = settings.ENABLE_TEMPLATE_RIGHTS_VALIDATION
        self.ca = settings.CA
        self.intermediary = settings.INTERMEDIARY
        self.chain = settings.CHAIN
        self.clean()

    class Meta:
        abstract = True


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


class ProjectSettings(
    PkiFieldsMixin,
    EmailSettingsFieldsMixin,
    SingletonModel,
        ):

    def save(self, *args, **kwargs):
        if not self.id:
            self.update_fields()
            self.update_mail_settings()
            super().save(*args, **kwargs)
        if self.id:
            old_days_to_expire = self.days_to_expire
            super().save(*args, **kwargs)
            new_days_to_expire = self.days_to_expire
            if old_days_to_expire != new_days_to_expire:
                hosts = Host.objects.all()
                hosts.update(days_to_expire=new_days_to_expire)

    def update_settings(self, *args, **kwargs):
        self.update_fields()
        self.update_mail_settings()
        self.save()

    @classmethod
    def get_solo(cls):
        objects = cls.objects.filter(pk=cls.singleton_instance_id)
        if objects.exists():
            obj = objects.first()
        else:
            obj = cls(pk=cls.singleton_instance_id)
            obj.update_settings()
        return obj

    def __str__(self):
        return f'{self.id}'

    class Meta:
        verbose_name = 'ProjectSettings'
        verbose_name_plural = 'ProjectSettings'


class AllowedCN(models.Model):
    project_settings = models.ForeignKey(to='pki_bridge.ProjectSettings', on_delete=models.SET_NULL, blank=True, null=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        project_settings = ProjectSettings.get_solo()
        self.project_settings = project_settings
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.name}'

    class Meta:
        verbose_name = 'Allowed CN'
        verbose_name_plural = 'Allowed CNs'


class Port(models.Model):
    project_settings = models.ForeignKey(to='pki_bridge.ProjectSettings', on_delete=models.SET_NULL, blank=True, null=True)
    name = models.PositiveIntegerField()
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        project_settings = ProjectSettings.get_solo()
        self.project_settings = project_settings
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.name}'

    class Meta:
        verbose_name = "Port"
        verbose_name_plural = "Ports"
