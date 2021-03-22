import ldap
from .ldaphelper import get_search_results

import config


def search(dn, filter, attributes, user_dn, password):
    l = ldap.initialize(config.ldap('main', 'server_address'))
    l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    l.set_option(ldap.OPT_REFERRALS, 0)

    l.simple_bind_s(user_dn, password)

    result_data = l.search_s(dn, ldap.SCOPE_SUBTREE, filter, attributes)

    l.unbind()

    return get_search_results(result_data)
