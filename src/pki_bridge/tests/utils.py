from django.conf import settings


def get_pem():
    with open(settings.TEST_CERT_FILEPATH) as f:
        pem = f.read()
    return pem
