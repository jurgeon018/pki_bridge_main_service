from django.db import models


class TimeMixin(models.Model):
    created = models.DateTimeField(auto_now=False, auto_now_add=True)
    updated = models.DateTimeField(auto_now=True, auto_now_add=False)

    class Meta:
        abstract = True


class ActiveMixin(models.Model):
    is_active = models.BooleanField(default=True)

    class Meta:
        abstract = True


class AuthorMixin(models.Model):
    created_by = models.ForeignKey(
        to="pki_bridge.ProjectUser", on_delete=models.SET_NULL, blank=True, null=True,
        related_name="%(app_label)s_%(class)s_created_by",
    )
    last_updated_by = models.ForeignKey(
        to="pki_bridge.ProjectUser", on_delete=models.SET_NULL, blank=True, null=True,
        related_name="%(app_label)s_%(class)s_last_updated_by",
    )

    class Meta:
        abstract = True
