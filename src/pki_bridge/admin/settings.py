from solo.admin import SingletonModelAdmin
from pki_bridge.models import ProjectSettings, AllowedCN, Port
from django.contrib import admin


class AllowedCNInline(admin.TabularInline):
    model = AllowedCN
    classes = ['collapse']
    extra = 0


class PortInline(admin.TabularInline):
    model = Port
    classes = ['collapse']
    extra = 0


@admin.register(ProjectSettings)
class ProjectSettingsAdmin(SingletonModelAdmin):
    inlines = [
        AllowedCNInline,
        PortInline,
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


@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
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
        'is_active'
    ]
    search_fields = [
        'name',
    ]
