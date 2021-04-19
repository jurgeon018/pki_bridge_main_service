from django.contrib.auth.models import AbstractUser
from django.db import models
from pki_bridge.models.mixins import ActiveMixin
from pki_bridge.models.mixins import AuthorMixin
from pki_bridge.models.mixins import TimeMixin


class Command(TimeMixin, ActiveMixin, AuthorMixin):
    name = models.CharField(max_length=255)
    url = models.URLField()
    description = models.TextField()

    def __str__(self):
        return f"{self.name}"

    class Meta:
        verbose_name = "Command"
        verbose_name_plural = "Commands"


class ProjectUser(AbstractUser):
    email = models.EmailField(blank=True, null=True, unique=True)
    templates = models.ManyToManyField(to="pki_bridge.Template", blank=True)

    def __str__(self):
        return f"{self.username}"

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
