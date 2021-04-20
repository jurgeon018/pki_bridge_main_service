from admin_auto_filters.filters import AutocompleteFilter
from django.contrib.admin import SimpleListFilter


class NetworkFilter(AutocompleteFilter):
    title = 'network'
    field_name = 'network'


class HostFilter(AutocompleteFilter):
    title = 'host'
    field_name = 'host'

class LastScanFilter(AutocompleteFilter):
    title = 'last scan'
    field_name = 'last_scan'


class RequesterFilter(AutocompleteFilter):
    title = 'requester'
    field_name = 'requester'


class CertificateFilter(AutocompleteFilter):
    title = 'certificate'
    field_name = 'certificate'


class CertificateRequestFilter(AutocompleteFilter):
    title = 'certificate_request'
    field_name = 'certificate_request'


class CertificatePresenceFilter(SimpleListFilter):
    title = 'has certificate'
    parameter_name = 'has_certificate'

    def lookups(self, request, model_admin):
        return [
            ('not_null', 'Has certificate'),
            ('null', 'Doesnt have certificate'),
        ]

    def queryset(self, request, queryset):
        if self.value() == 'not_null':
            return queryset.distinct().filter(certificate__isnull=False)
        if self.value() == 'null':
            return queryset.distinct().filter(certificate__isnull=True)


class NetworkSimpleFilter(SimpleListFilter):
    title = 'has network'
    parameter_name = 'has_network'

    def lookups(self, request, model_admin):
        return [
            ('not_null', 'Has network'),
            ('null', 'Doesnt have network'),
        ]

    def queryset(self, request, queryset):
        if self.value() == 'not_null':
            return queryset.distinct().filter(network__isnull=False)
        if self.value() == 'null':
            return queryset.distinct().filter(network__isnull=True)


class ErrorMessageFilter(SimpleListFilter):
    title = 'Error message status'
    parameter_name = 'error_message'

    def lookups(self, request, model_admin):
        return [
            ('not_null', 'Has error message'),
            ('null', 'Doesnt have error message'),
        ]

    def queryset(self, request, queryset):
        if self.value() == 'not_null':
            return queryset.distinct().filter(error_message__isnull=False)
        if self.value() == 'null':
            return queryset.distinct().filter(error_message__isnull=True)
