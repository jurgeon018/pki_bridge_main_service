from django.contrib import admin
from pki_bridge.models import (
    Note,
    CertificateRequest,
)
from pki_bridge.admin.mixins import (
    BaseMixin,
)


class NoteInline(admin.TabularInline):
    model = Note
    exclude = []
    readonly_fields = [
        'created',
        'updated',
        'created_by',
        'last_updated_by',
    ]
    extra = 0


@admin.register(CertificateRequest)
class CertificateRequestAdmin(BaseMixin, admin.ModelAdmin):
    inlines = [
        NoteInline,
    ]
    search_fields = [
        'email',
        'certificate',
    ]

    list_editable = [
        'email',
        'certificate',
    ]
    list_display = [
        'id',
        'email',
        'certificate',
    ]
    list_display_links = [
        'id',
    ]



@admin.register(Note)
class NoteAdmin(BaseMixin, admin.ModelAdmin):
    list_display = [
        'id',
        "certificate_request",
        "text",
        'created',
        'updated',
    ]
    list_editable = [
        'certificate_request',
        'text',
    ]
    list_display_links = [
        'id',
    ]
    autocomplete_fields = [
        'certificate_request',
    ]

    search_fields = [
        'text',
    ]

