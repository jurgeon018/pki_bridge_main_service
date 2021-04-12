from django.contrib import admin
from django.utils.html import mark_safe


from pki_bridge.core.utils import get_admin_url
from pki_bridge.admin.filters import (
    HostFilter,
    NetworkFilter,
    CertificateRequestFilter,
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
    ]
    list_display = [
        'id',
        'is_active',
        'name',
        'network',
        'contacts',
    ]
    autocomplete_fields = [
        'network',
    ]
    list_display_links = [
        'id',
    ]
    list_filter = [
        NetworkFilter,

    ]


@admin.register(HostScan)
class HostScanAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = [
        'id',
        'host',
        'created',
        'updated',
    ]
    autocomplete_fields = [
        'host',
    ]
    list_filter = [

        HostFilter,
        'created',
        'updated',
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
        'created',
        'updated',
    ]
    list_filter = [
        CertificateRequestFilter,
        'created',
        'updated',
    ]
    autocomplete_fields = [
        'certificate_request',
    ]
