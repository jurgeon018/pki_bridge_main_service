import re


def check_certificate_id(id):
    return re.match('^\d+$', id) is not None
