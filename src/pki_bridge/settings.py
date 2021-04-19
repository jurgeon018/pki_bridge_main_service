import re
from pathlib import Path

from decouple import config
from decouple import Csv


BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = config("SECRET_KEY")
DEBUG = config("DEBUG")
DOMAIN = config("DOMAIN", cast=str)
ALLOWED_HOSTS = [
    "127.0.0.1",
    "localhost",
    DOMAIN,
    "*",
]
INSTALLED_APPS = [
    "admin_auto_filters",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    "rangefilter",
    "rest_framework",
    "solo",
    "pki_bridge",
]
APPEND_SLASH = True
# APPEND_SLASH = False
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "pki_bridge.middleware.DisabledViewMiddleware",
]
ROOT_URLCONF = "pki_bridge.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]
WSGI_APPLICATION = "pki_bridge.wsgi.application"
if config("DB") == "sqlite3":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
elif config("DB") == "postgres":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql_psycopg2",
            "NAME": config("DB_NAME"),
            "USER": config("DB_USER"),
            "PASSWORD": config("DB_PASSWORD"),
            "HOST": config("DB_HOST"),
            "PORT": config("DB_PORT"),
        }
    }
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.memcached.MemcachedCache",
        "LOCATION": config("CACHES_LOCATION"),
    },
}
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "static_root"
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
AUTH_USER_MODEL = "pki_bridge.ProjectUser"
SITE_ID = 1

# project settings
with open(BASE_DIR / "fixtures" / "cer.cer") as f:
    CA = f.read()
with open(BASE_DIR / "fixtures" / "cer.cer") as f:
    INTERMEDIARY = f.read()
with open(BASE_DIR / "fixtures" / "chain.cer") as f:
    CHAIN = f.read()
PORTS = config("PORTS", cast=Csv())
LDAP_USERNAME = config("LDAP_USERNAME", cast=str)
LDAP_PASSWORD = config("LDAP_PASSWORD", cast=str)
ALLOWED_REQUESTS = config("ALLOWED_REQUESTS", cast=int)
RESET_PERIOD = config("RESET_PERIOD", cast=int)
SCAN_TIMEOUT = config("SCAN_TIMEOUT", cast=int)
DAYS_TO_EXPIRE = config("DAYS_TO_EXPIRE", cast=int)
CERTIFICATES_PER_PAGE = config("CERTIFICATES_PER_PAGE", cast=int)
HOSTS_PER_PAGE = config("HOSTS_PER_PAGE", cast=int)
ALLOWED_CNS = [
    "DigiCert SHA2 Secure Server CA",
    "GTS CA 1O1",
]
ENABLE_MAIL_NOTIFICATIONS = config("ENABLE_MAIL_NOTIFICATIONS", cast=bool)
SCANNER_SECRET_KEY = config("SCANNER_SECRET_KEY", cast=str)
ENABLE_TEMPLATE_RIGHTS_VALIDATION = config("ENABLE_TEMPLATE_RIGHTS_VALIDATION", cast=bool)
VALIDATE_TEMPLATES = config("VALIDATE_TEMPLATES", cast=bool)
UPDATE_TEMPLATES_FROM_CA = config("UPDATE_TEMPLATES_FROM_CA", cast=bool)
ALLOW_USE_FILE_AS_LDAP_RESULTS = config("ALLOW_USE_FILE_AS_LDAP_RESULTS", cast=bool)

TEST_CERT_FILEPATH = BASE_DIR / "fixtures" / "test_certificate.pem"
TEST_CERT2_FILEPATH = BASE_DIR / "fixtures" / "cer.cer"
TEST_CSR_FILEPATH = "src/test_data/pki_test.csr"
WINDOWS_SECRET_KEY = "windows_service_69018"
WINDOWS_SCHEMA = config("WINDOWS_SCHEMA")
WINDOWS_HOST = config("WINDOWS_HOST")
WINDOWS_PORT = config("WINDOWS_PORT")
WINDOWS_URL = f"{WINDOWS_SCHEMA}://{WINDOWS_HOST}:{WINDOWS_PORT}"

# local project settings
MOCK_INTERMEDIARY_RESPONSE = True
# mail

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

# logging

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "short": {"format": "%(name)-12s %(levelname)-8s %(message)s"},
        "long": {"format": "%(asctime)s %(name)-16s %(funcName)-12s %(levelname)-8s %(message)s"},
        "full": {
            "format": "\nasctime: %(asctime)-12s \ncreated: %(created)-12f \nfilename: %(filename)-12s \nfuncName: %(funcName)-12s \nlevelname: %(levelname)-12s \nlevelno: %(levelno)-12s \nlineno: %(lineno)-12d \nmessage: %(message)-12s \nmodule: %(module)-12s \nmsecs: %(msecs)-12d \nname: %(name)-12s \npathname: %(pathname)-12s \nprocess: %(process)-12d \nprocessName: %(processName)-12s \nrelativeCreated: %(relativeCreated)-12d \nthread: %(thread)-12d \nthreadName: %(threadName)-12s\n"
        },
    },
    "handlers": {
        "null": {
            "level": "DEBUG",
            "class": "logging.NullHandler",
        },
        "console": {"level": "DEBUG", "class": "logging.StreamHandler", "formatter": "short"},
        "debug_file": {"level": "DEBUG", "class": "logging.FileHandler", "formatter": "long", "filename": BASE_DIR / "debug.log"},
        "warning_file": {"level": "WARNING", "class": "logging.FileHandler", "formatter": "long", "filename": BASE_DIR / "warning.log"},
        "error_file": {"level": "ERROR", "class": "logging.FileHandler", "formatter": "long", "filename": BASE_DIR / "error.log"},
    },
    "loggers": {
        "": {
            "level": "WARNING",
            "handlers": [
                "debug_file",
                "warning_file",
                "error_file",
            ],
            "propagate": False,
        },
    },
}
