from decouple import config
from decouple import Csv

from .django import BASE_DIR

with open(BASE_DIR / "fixtures" / "cer.cer") as f:
    CA = f.read()
with open(BASE_DIR / "fixtures" / "cer.cer") as f:
    INTERMEDIARY = f.read()
with open(BASE_DIR / "fixtures" / "chain.cer") as f:
    CHAIN = f.read()
PORTS = config("PORTS", cast=Csv())
VAULT_TOKEN = config("VAULT_TOKEN", cast=str)
LDAP_USERNAME = config("LDAP_USERNAME", cast=str)
LDAP_PASSWORD = config("LDAP_PASSWORD", cast=str)
ALLOWED_REQUESTS = config("ALLOWED_REQUESTS", cast=int)
RESET_PERIOD = config("RESET_PERIOD", cast=int)
SCAN_TIMEOUT = config("SCAN_TIMEOUT", cast=int)
DAYS_TO_EXPIRE = config("DAYS_TO_EXPIRE", cast=int)
CERTIFICATES_PER_PAGE = config("CERTIFICATES_PER_PAGE", cast=int)
HOSTS_PER_PAGE = config("HOSTS_PER_PAGE", cast=int)
ALLOWED_CNS = [
    "Vault PRD Intermediate CA fpprod.corp",
    "Leonteq Class 3 Issuing CA",
    "Infrastructure Services",
    # "DigiCert SHA2 Secure Server CA",
    # "GTS CA 1O1",
]
ENABLE_MAIL_NOTIFICATIONS = config("ENABLE_MAIL_NOTIFICATIONS", cast=bool)
SCANNER_SECRET_KEY = config("SCANNER_SECRET_KEY", cast=str)
ENABLE_TEMPLATE_RIGHTS_VALIDATION = config("ENABLE_TEMPLATE_RIGHTS_VALIDATION", cast=bool)
VALIDATE_TEMPLATES = config("VALIDATE_TEMPLATES", cast=bool)
UPDATE_TEMPLATES_FROM_CA = config("UPDATE_TEMPLATES_FROM_CA", cast=bool)
ALLOW_USE_FILE_AS_LDAP_RESULTS = config("ALLOW_USE_FILE_AS_LDAP_RESULTS", cast=bool)
DEFAULT_CONTACTS_FOR_NOTIFICATIONS = config("DEFAULT_CONTACTS_FOR_NOTIFICATIONS", cast=str)

TEST_CERT_FILEPATH = BASE_DIR / "fixtures" / "test_certificate.pem"
TEST_CERT2_FILEPATH = BASE_DIR / "fixtures" / "cer.cer"
TEST_CSR_FILEPATH = "src/test_data/pki_test.csr"

# for local development
MOCK_INTERMEDIARY_RESPONSE = True
