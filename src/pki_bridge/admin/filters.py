from admin_auto_filters.filters import AutocompleteFilter


class NetworkFilter(AutocompleteFilter):
    title = 'network'
    field_name = 'network'


class HostFilter(AutocompleteFilter):
    title = 'host'
    field_name = 'host'


class RequesterFilter(AutocompleteFilter):
    title = 'requester'
    field_name = 'requester'


class CertificateFilter(AutocompleteFilter):
    title = 'certificate'
    field_name = 'certificate'

class CertificateRequestFilter(AutocompleteFilter):
    title = 'certificate_request'
    field_name = 'certificate_request'


