import hvac
import config
import os
import psycopg2
import psycopg2.extras as extras
import db.secrets as secrets
from .entries import search


def populate():
    vault_client = hvac.Client(config.vault('url'))
    vault_client.token = os.environ['VAULT_TOKEN']
    wsig_keys = vault_client.secrets.kv.read_secret_version(path='wsig')['data']['data']

    db = psycopg2.connect("dbname='%s' host='%s' user='%s' password='%s'" %
                          (config.db('name'), config.db('host'),
                           wsig_keys['db_username'], wsig_keys['db_password']))

    res = search(config.ldap('main', 'search_dn'), config.ldap('main', 'search_filter'),
                 wsig_keys['ldap_userdn'], wsig_keys['ldap_password'])
    try:
        with db.cursor() as cursor:
            insert_params = []
            for r in res:
                for email_bytes in r.attrs['mail']:
                    email = email_bytes.decode("utf-8")
                    insert_params.append((email,))

            sql = "TRUNCATE TABLE ldap_user;"
            cursor.execute(sql)

            sql = "INSERT INTO ldap_user(email) VALUES %s;"
            extras.execute_values(cursor, sql, insert_params, template=None, page_size=100)

            db.commit()
    finally:
        db.rollback()
