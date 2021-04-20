from django.contrib import admin
from django.utils.html import mark_safe
from rangefilter.filter import DateRangeFilter, DateTimeRangeFilter

import json

from pki_bridge.core.utils import get_admin_url
from pki_bridge.admin.filters import (
    HostFilter,
    NetworkFilter,
    CertificateRequestFilter,
    ErrorMessageFilter,
    CertificateFilter,
    NetworkSimpleFilter,
    LastScanFilter,
    CertificatePresenceFilter,
)
from pki_bridge.models import (
    Network,
    Host,
    HostScan,
    CertificateRequestScan,
)
from pki_bridge.admin.mixins import (
    BaseMixin,
)


@admin.register(Network)
class NetworkAdmin(BaseMixin, admin.ModelAdmin):
    search_fields = [
        'name',
        'ip',
        'mask',
        'vlan_id',
        'contacts',
    ]
    list_display = [
        'id',
        'name',
        'ip',
        'mask',
        'vlan_id',
        'contacts',
    ]
    list_display_links = [
        'id',
    ]
    list_editable = [
        'name',
        'ip',
        'mask',
        'vlan_id',
        'contacts',
    ]
    list_filter = [
        'mask',
    ]


@admin.register(Host)
class HostAdmin(BaseMixin, admin.ModelAdmin):

    def get_readonly_fields(self, request, obj):
        readonly_fields = super().get_readonly_fields(request, obj)
        return readonly_fields + [
            "get_last_scan",
        ]

    def get_fields(self, request, obj):
        fields = super().get_fields(request, obj)
        fields.remove('last_scan')
        return fields

    def get_last_scan(self, obj=None):
        if obj.last_scan:
            link = get_admin_url(obj.last_scan)
            last_scan = mark_safe(f'<a target="_blank" href="{link}">{obj.created}</a>')
        else:
            last_scan = '---'
        return last_scan
    
    get_last_scan.short_description = 'Last scan'

    search_fields = [
        'name',
        'contacts',
    ]
    list_editable = [
        'name',
        'contacts',
        'is_active',
        'days_to_expire',
    ]
    list_display = [
        'id',
        'is_active',
        'name',
        'network',
        'contacts',
        'days_to_expire',
        'created',
        'updated',
    ]
    autocomplete_fields = [
        'network',
    ]
    list_display_links = [
        'id',
    ]
    list_filter = [
        NetworkFilter,
        NetworkSimpleFilter,
        LastScanFilter,
        'created',
        'updated',
        ('created', DateTimeRangeFilter),
        ('updated', DateTimeRangeFilter),
    ]



@admin.register(HostScan)
class HostScanAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

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

    readonly_fields = [
        'get_certificate_page',
        'get_certificate_json',
        'get_certificate_info',
    ]
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
                'certificate',
                'get_certificate_page',
                'host',
                'port',
                'error_message',
                'created',
                'updated',
            ],
        }],
    ]
    list_display = [
        'id',
        'host',
        'port',
        'certificate',
        'error_message',
        'created',
        'updated',
    ]
    autocomplete_fields = [
        'host',
    ]
    list_filter = [
        CertificateFilter,
        HostFilter,
        ErrorMessageFilter,
        CertificatePresenceFilter,
        "port",
        ('created', DateRangeFilter),
        ('updated', DateRangeFilter),
        'created',
        'updated',

        ('certificate__valid_from', DateRangeFilter),
        ('certificate__valid_till', DateRangeFilter),
        'certificate__valid_from',
        'certificate__valid_till',
        'certificate__issued_to',
        'certificate__issuer_ou',
        'certificate__issuer_cn',
        'certificate__issued_o',
        'certificate__issuer_c',
        'certificate__issuer_o',
        # 'certificate__cert_sans',
    ]


@admin.register(CertificateRequestScan)
class CertificateRequestScanAdmin(admin.ModelAdmin):

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = [
        'id',
        'certificate_request',
        'error_message',
        'created',
        'updated',
    ]
    list_filter = [
        CertificateRequestFilter,
        ErrorMessageFilter,
        'created',
        'updated',
        ('created', DateTimeRangeFilter),
        ('updated', DateTimeRangeFilter),

    ]
    autocomplete_fields = [
        'certificate_request',
    ]
    def get_certificate_info(self, obj=None):
        if obj is None:
            return None
        try:
            certificate_info = obj.certificate_request.certificate.cert_info
            certificate_info = certificate_info.replace('    ', '____')
        except Exception as e:
            certificate_info = f'Couldnt convert certificate to text due to error: \n{e}.'
        return certificate_info

    get_certificate_info.short_description = 'Certificate info'

    def get_certificate_json(self, obj=None):
        if obj is None:
            return None
        try:
            certificate_json = obj.certificate_request.certificate.cert_json
            certificate_json = json.dumps(certificate_json, indent=4)
            certificate_json = certificate_json.replace('    ', '____')
        except Exception as e:
            certificate_json = f'Couldnt convert certificate to json due to error: \n{e}.'
        return certificate_json

    get_certificate_json.short_description = 'Certificate json'

    def get_certificate_page(self, obj=None):
        from pki_bridge.core.utils import get_admin_url
        from django.utils.html import mark_safe
        if obj.certificate_request and obj.certificate_request.certificate:
            link = get_admin_url(obj.certificate_request.certificate)
            certificate_page = mark_safe(f'<a target="_blank" href="{link}">{obj.created}</a>')
        else:
            certificate_page = '---'
        return certificate_page
    
    get_certificate_page.short_description = 'Certificate page'

    def get_certificate_request_page(self, obj=None):
        from pki_bridge.core.utils import get_admin_url
        from django.utils.html import mark_safe
        if obj.certificate_request:
            link = get_admin_url(obj.certificate_request)
            certificate_request_page = mark_safe(f'<a target="_blank" href="{link}">{obj.created}</a>')
        else:
            certificate_request_page = '---'
        return certificate_request_page
    
    get_certificate_request_page.short_description = 'Certificate request page'

    readonly_fields = [
        'get_certificate_request_page',
        'get_certificate_page',
    ]
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
                'certificate_request',
                'error_message',
                'created',
                'updated',
                'get_certificate_request_page',
                'get_certificate_page',
            ],
        }],
    ]
