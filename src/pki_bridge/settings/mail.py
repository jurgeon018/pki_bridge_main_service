import re

from decouple import config

EMAIL_BACKEND = "pki_bridge.backends.ConfiguredEmailBackend"
# EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_SUBJECT_PREFIX = "[Pki bridge]"
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD")
# EMAIL_HOST_USER = 'menan@leonteq.com'
EMAIL_HOST_USER = "andrey.mendela@leonteq.com"
EMAIL_HOST = "devmail.fpprod.corp"
# EMAIL_HOST = 'mail.fpprod.corp'
EMAIL_PORT = 465
EMAIL_USE_SSL = True
EMAIL_USE_TLS = False
ADMINS = (("andrey mendela", "andrey.mendela@leonteq.com"),)
MANAGERS = ADMINS
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
SERVER_EMAIL = EMAIL_HOST_USER
IGNORABLE_404_URLS = [
    re.compile(r"\.(php|cgi)$"),
    re.compile(r"^/phpmyadmin/"),
]
