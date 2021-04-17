from django.contrib import admin
from pki_bridge.models import (
    Note,
    CertificateRequest,
    Requester,
    Certificate,
)
from pki_bridge.admin.mixins import (
    BaseMixin,
)
from pki_bridge.admin.filters import (
    RequesterFilter,
    CertificateFilter,
)
import json


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


@admin.register(Requester)
class RequesterAdmin(BaseMixin, admin.ModelAdmin):
    search_fields = [
        'email',
    ]
    list_display = [
        'id',
        'email',
        'created',
        'updated',
    ]
    readonly_fields = [
        'id',
        'email',
    ]


@admin.register(Certificate)
class Certificate(BaseMixin, admin.ModelAdmin):
    def has_change_permission(self, request, obj=None):
        return False

    list_display = [
        'id',
        'issued_to',
    ]
    list_display_links = [
        'id',
        'issued_to',
    ]


@admin.register(CertificateRequest)
class CertificateRequestAdmin(BaseMixin, admin.ModelAdmin):

    def get_certificate_text(self, obj=None):
        if obj is None:
            return None
        try:
            certificate_text = obj.certificate_text
            certificate_text = certificate_text.replace('    ', '____')
        except Exception as e:
            certificate_text = f'Couldnt convert certificate to text due to error: \n{e}.'
        return certificate_text

    get_certificate_text.short_description = 'Certificate info'

    def get_certificate_json(self, obj=None):
        if obj is None:
            return None
        try:
            certificate_json = obj.certificate_json
            certificate_json = json.dumps(certificate_json, indent=4)
            certificate_json = certificate_json.replace('    ', '____')
        except Exception as e:
            certificate_json = f'Couldnt convert certificate to json due to error: \n{e}.'
        return certificate_json

    get_certificate_json.short_description = 'Certificate json'

    fieldsets = [
        # ['Certificate text', {
        #     'classes': ['collapse'],
        #     'fields': [
        #         'get_certificate_text',
        #     ],
        # }],
        # ['Certificate json', {
        #     'classes': ['collapse'],
        #     'fields': [
        #         'get_certificate_json',
        #     ],
        # }],
        [None, {
            'fields': [
                'id',
                'requester',
                'template',
                'SAN',
                'domain',
                'csr',
                'certificate',
            ],
        }],
    ]
    readonly_fields = [
        # 'get_certificate_text',
        # 'get_certificate_json',
        'id',
        'requester',
        'template',
        'SAN',
        'domain',
        'csr',
        'certificate',
    ]
    list_display_links = [
        'id',
        'requester',
        'domain',
        'template',
    ]
    inlines = [
        NoteInline,
    ]
    search_fields = [
        'requester__email',
        'template',
        'domain',
    ]
    list_filter = [
        RequesterFilter,
        CertificateFilter,
        'domain',
        'template',
    ]
    list_display = [
        'id',
        'requester',
        'domain',
        'template',
        'certificate',
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
