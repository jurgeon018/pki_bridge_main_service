from django.conf import settings

import logging
import subprocess

from pki_bridge.conf import db_settings
from django.conf import settings


logger = logging.getLogger(__name__)


def get_ldap_result():
    # username = settings.LDAP_USERNAME
    # password = settings.LDAP_PASSWORD
    username = db_settings.ldap_username
    password = db_settings.ldap_password
    search_output = perform_ldap_search(
        ldap_username=username,
        ldap_password=password,
        attributes=['mail', ],
    )
    if search_output == '' and db_settings.allow_use_file_as_ldap_results:
        with open(settings.BASE_DIR / 'ldap_responses' / 'ldap_result.txt', 'r') as f:
            search_output = f.read()
    elif search_output == '' and not db_settings.allow_use_file_as_ldap_results:
        msg = 'Ldap didnt return any result.'
        logger.error(msg)
        return []
    search_output = search_output.replace('\n ', '')
    search_output = search_output.split('\n')
    ldap_result = parse_search_output(search_output)
    return ldap_result


def entry_is_in_ldap(field, ldap_field='mail'):
    ldap_result = get_ldap_result()
    for entry in ldap_result:
        if entry.get(ldap_field) == field:
            was_found = True
            break
    else:
        was_found = False
    return was_found

from pki_bridge.core.utils import (
    run,
)


def perform_ldap_search(ldap_username, ldap_password, attributes=['sAMAccountName', 'mail', ]):
    assert ldap_username is not None
    assert ldap_password is not None
    # group = 'cn=FpprodLdap,ou=Service Accounts,ou=Delegation,dc=fpprod,dc=corp'
    # group = 'cn=domain users,ou=users,dc=fpprod,dc=corp'
    base_dn = 'dc=fpprod,dc=corp'
    args = [
        '/usr/bin/ldapsearch',
        '-LLL', '-H', 'ldap://fpprod.corp', '-x',
        '-D', ldap_username,
        '-w', ldap_password,
        '-E', 'pr=1000/noprompt',
        '-b', base_dn,
        '-s', 'sub',
        '-x',
        # '(&(objectClass=user)(sAMAccountName=*)(memberof=cn='+group+',ou=Groups,ou=Leonteq,dc=fpprod,dc=corp))'
        # f'(&(objectClass=user)(sAMAccountName=*)(memberof={group}))'
    ]
    for a in attributes:
        args.append(a)
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE)
        output, err = process.communicate()
        process.wait()
        result = output.decode()
    except Exception as e:
        print(e, args)
        result = ""
    return result


def parse_search_output(lines):
    result = [{}]
    for line in lines:
        line = line.rstrip()
        if line == "":
            result.append({})
            continue
        if line.count(':') > 1:
            attr_split = line.split(":", 1)
        else:
            attr_split = line.split(":")
        attr_name, attr_value = attr_split
        attr_value = attr_value.strip()
        attr_name = attr_name.strip()
        result[len(result) - 1][attr_name] = attr_value
    return [r for r in result if r != {}]
