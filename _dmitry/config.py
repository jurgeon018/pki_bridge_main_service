import configparser


CONFIG_FILE_PATH = "./config/main_service.ini"
MAIL_CONFIG_FILE_PATH = "./config/mail.ini"
CSR_CONFIG_FILE_PATH = "./config/csr.ini"
LDAP_CONFIG_FILE_PATH = "./config/ldap.ini"
TEMPLATE_CONFIG_FILE_PATH = "./config/template.ini"

config = configparser.RawConfigParser()
config.read(CONFIG_FILE_PATH)

mail_config = configparser.RawConfigParser()
mail_config.read(MAIL_CONFIG_FILE_PATH)

csr_config = configparser.RawConfigParser()
csr_config.read(CSR_CONFIG_FILE_PATH)

ldap_config = configparser.RawConfigParser()
ldap_config.read(LDAP_CONFIG_FILE_PATH)

template_config = configparser.ConfigParser()
template_config.read(TEMPLATE_CONFIG_FILE_PATH)


def main(section, param_name):
    return config.get(section, param_name)


def has_section(section):
    return config.has_section(section)


def mail(section, param_name):
    return mail_config.get(section, param_name)


def csr(section, param_name):
    return csr_config.get(section, param_name)


def db(option):
    return config.get('db', option)


def vault(option):
    return config.get('vault', option)


def ldap(section, option):
    return ldap_config.get(section, option)


def template(section, option):
    return template_config.get(section, option)
