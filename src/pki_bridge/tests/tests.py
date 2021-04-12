import pytest
from unittest.mock import patch
from django.conf import settings

from pki_bridge.models import (
    Template,
    ProjectSettings,
    Certificate,
    Requester,
    CertificateRequest,
)
from pki_bridge.conf import db_settings

# TODO test migrations
# TODO test admin
# TODO test views
# TODO test scanner

@pytest.mark.django_db
@patch('pki_bridge.views.get_intermediary_response')
def test_signcert(mock_intermediary_response, client):
    assert Certificate.objects.all().count() == 0
    assert Requester.objects.all().count() == 0
    assert CertificateRequest.objects.all().count() == 0
    test_cert_filepath = settings.BASE_DIR / 'fixtures' / 'test_certificate.pem'
    with open(test_cert_filepath, 'r', encoding='utf-8') as cert_file:
        mock_intermediary_response.return_value = {
            'certificate': cert_file.read()
        }
    with open('src/test_data/pki_test.csr') as f:
        data = {
            "requester": "andrey.mendela@leonteq.com",
            "template": "LeonteqWebSrvManualEnroll",
            "SAN": "altname1, altname2, altname3",
            "note": "note test example",
            "env": "env",
            "certformat": "pem",
            'csr': f,
        }
        response = client.post('/api/v1/signcert/', data=data)
    content = response.content
    result = str(content)
    assert response.status_code == 200
    assert Certificate.objects.all().count() == 1
    assert CertificateRequest.objects.all().count() == 1
    assert Requester.objects.all().count() == 1
