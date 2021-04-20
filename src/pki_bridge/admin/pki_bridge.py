from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import mark_safe
from django.urls import reverse

from pki_bridge.admin.mixins import (
    BaseMixin,
)
from pki_bridge.models import (
    Template,
    Command,
    ProjectUser,
)

from rangefilter.filter import DateTimeRangeFilter
@admin.register(Template)
class TemplateAdmin(BaseMixin, admin.ModelAdmin):

    list_display = [
        'id',
        'name',
        'description',
        'created',
        'updated',
    ]
    list_editable = [
        'name',
        'description',
    ]
    list_display_links = [
        'id',
    ]
    search_fields = [
        'name',
    ]
    list_filter = [
        'created',
        'updated',
        ('created', DateTimeRangeFilter),
        ('updated', DateTimeRangeFilter),

    ]


@admin.register(Command)
class CommandAdmin(BaseMixin, admin.ModelAdmin):

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    list_display_links = [
        'id',
    ]
    list_display = [
        'id',
        'is_active',
        'name',
        'url',
        'description',
        'created',
        'updated',
    ]
    list_editable = [
        'is_active',
        'description',
    ]
    readonly_fields = [
        'url',
        'name',
    ]
    search_fields = [
        'name',
    ]
    list_filter = [
        'created',
        'updated',
        ('created', DateTimeRangeFilter),
        ('updated', DateTimeRangeFilter),
    ]


class TemplateInline(admin.TabularInline):
    model = ProjectUser.templates.through
    extra = 0
    verbose_name = 'Template right'
    verbose_name_plural = 'Template rights'


@admin.register(ProjectUser)
class ProjectUserAdmin(UserAdmin):
    search_fields = ['username']
    inlines = [
        TemplateInline,
    ]
