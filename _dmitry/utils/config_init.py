import os


def db():
    with open('config/main_service.ini', 'w') as main_config:
        main_config.write('[windows_service]\nbase_url:%s\n\n' % os.environ['WINDOWS_SERVICE_URL'])
        main_config.write('[vault]\nurl:%s\ntoken:%s\n\n' % (os.environ['VAULT_ADDR'], os.environ['VAULT_TOKEN']))
        main_config.write('[db]\nname:%s\nhost:%s\n\n' % (os.environ['POSTGRES_DBNAME'], os.environ['POSTGRES_HOST']))


def mail():
    with open('config/mail.ini', 'w') as mail_config:
        mail_config.write('[smtp]\nhost:%s\nport=%s\n' %
                          (os.environ['MAIL_HOST'], os.environ['MAIL_PORT']))
        mail_config.write('[retry]\ncount=5\ninterval=1\n')


def ldap():
    with open('config/ldap.ini', 'w') as ldap_config:
        ldap_config.write('[main]\nserver_address:%s\nsearch_dn:%s' %
                          (os.environ['LDAP_ADDR'], os.environ['LDAP_SEARCH_DN']))

def main():
    db()
    mail()
    ldap()


if __name__ == '__main__':
    main()
