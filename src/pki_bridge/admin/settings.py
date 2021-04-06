from solo.admin import SingletonModelAdmin
from pki_bridge.models import ProjectSettings, AllowedCN
from django.contrib import admin


class AllowedCNInline(admin.TabularInline):
    model = AllowedCN
    classes = ['collapse']
    extra = 0


@admin.register(ProjectSettings)
class ProjectSettingsAdmin(SingletonModelAdmin):
    inlines = [
        AllowedCNInline,
    ]


@admin.register(AllowedCN)
class AllowedCNAdmin(admin.ModelAdmin):
    exclude = [
        'project_settings',
    ]
    list_display = [
        'id',
        'name',
        'is_active',
    ]
    list_display_links = [
        'id',
    ]
    list_editable = [
        'name',
        'is_active',
    ]
    search_fields = [
        'name',
    ]
