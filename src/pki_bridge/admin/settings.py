from solo.admin import SingletonModelAdmin
from pki_bridge.models import ProjectSettings
from django.contrib import admin


@admin.register(ProjectSettings)
class ProjectSettingsAdmin(SingletonModelAdmin):
    pass
