from admin_auto_filters.filters import AutocompleteFilter


class NetworkFilter(AutocompleteFilter):
    title = 'network'
    field_name = 'network'


class HostFilter(AutocompleteFilter):
    title = 'host'
    field_name = 'host'

