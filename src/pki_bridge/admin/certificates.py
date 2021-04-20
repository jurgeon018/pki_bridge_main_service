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
from rangefilter.filter import DateRangeFilter, DateTimeRangeFilter

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
class CertificateAdmin(BaseMixin, admin.ModelAdmin):

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj=None):
        # TODO v2 return True and hide all fields except "pem" on add_view 
        # return True
        return False

    readonly_fields = [
        "valid_days_to_expire",
        "validity_days",
        "is_expired",
        "is_from_different_ca",
        "is_self_signed",
    ]
    list_display = [
        'id',
        'valid_from',
        'valid_till',
        "valid_days_to_expire",
        "validity_days",
        "is_expired",
        "is_from_different_ca",
        "is_self_signed",
        'issued_to',
        'issuer_ou',
        'issuer_cn',
        'issued_o',
        'issuer_c',
        'issuer_o',
        # 'cert_sans',
        'created',
        'updated',
    ]
    list_filter = [
        'valid_from',
        'valid_till',
        ('valid_from', DateTimeRangeFilter),
        ('valid_till', DateTimeRangeFilter),
        'issued_to',
        'issuer_ou',
        'issuer_cn',
        'issued_o',
        'issuer_c',
        'issuer_o',
        # 'cert_sans',
        'created',
        'updated',
        ('created', DateTimeRangeFilter),
        ('updated', DateTimeRangeFilter),
    ]


@admin.register(CertificateRequest)
class CertificateRequestAdmin(BaseMixin, admin.ModelAdmin):

    def get_certificate_info(self, obj=None):
        if obj is None:
            return None
        try:
            certificate_info = obj.certificate.cert_info
            certificate_info = certificate_info.replace('    ', '____')
        except Exception as e:
            certificate_info = f'Couldnt convert certificate to text due to error: \n{e}.'
        return certificate_info

    get_certificate_info.short_description = 'Certificate info'

    def get_certificate_json(self, obj=None):
        if obj is None:
            return None
        try:
            certificate_json = obj.certificate.cert_json
            certificate_json = json.dumps(certificate_json, indent=4)
            certificate_json = certificate_json.replace('    ', '____')
        except Exception as e:
            certificate_json = f'Couldnt convert certificate to json due to error: \n{e}.'
        return certificate_json

    get_certificate_json.short_description = 'Certificate json'

    def get_certificate_page(self, obj=None):
        from pki_bridge.core.utils import get_admin_url
        from django.utils.html import mark_safe
        if obj.certificate:
            link = get_admin_url(obj.certificate)
            certificate_page = mark_safe(f'<a target="_blank" href="{link}">{obj.created}</a>')
        else:
            certificate_page = '---'
        return certificate_page
    
    get_certificate_page.short_description = 'Certificate page'

    fieldsets = [
        ['Certificate info', {
            'classes': ['collapse'],
            'fields': [
                'get_certificate_info',
            ],
        }],
        ['Certificate json', {
            'classes': ['collapse'],
            'fields': [
                'get_certificate_json',
            ],
        }],
        [None, {
            'fields': [
                'id',
                'requester',
                'template',
                'SAN',
                'domain',
                'csr',
                'certificate',
                'get_certificate_page',
            ],
        }],
    ]
    readonly_fields = [
        'get_certificate_info',
        'get_certificate_json',
        'get_certificate_page',
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
