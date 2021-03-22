from ldap.cidict import cidict


def get_search_results(results):
    """Given a set of results, return a list of LDAPSearchResult objects.
    """
    if len(results) == 0:
        return []
    if type(results) == tuple and len(results) == 2:
        (code, arr) = results
    elif type(results) == list:
        arr = results

    res = []
    for item in arr:
        res.append(LDAPSearchResult(item))

    return res


class LDAPSearchResult:
    dn = ''

    def __init__(self, entry_tuple):
        (dn, attrs) = entry_tuple
        if dn:
            self.dn = dn
        else:
            return
        self.attrs = cidict(attrs)

    def get_dn(self):
        return self.dn

    def __str__(self):
        result = "DN: " + self.dn + "\n"
        for a, v_list in self.attrs.items():
            result = result + "Name: " + a + "\n"
            for v in v_list:
                result = result + "  Value: " + str(v) + "\n"
        return result
