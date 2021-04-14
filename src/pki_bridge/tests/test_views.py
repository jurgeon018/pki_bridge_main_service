import pytest
from unittest.mock import patch
from django.conf import settings
from pki_bridge.models import (
    Template,
    ProjectSettings,
    Certificate,
    Requester,
    CertificateRequest,
    Command,
)
from pki_bridge.views import (
    entry_is_in_ldap,
    throttle_request,
    validate_SAN,
    validate_template_rights,
    create_certificate_request,
    get_intermediary_response,
    send_certificate_to_mail,
)
# from pki_bridge.conf import db_settings


class TestMiddlewares:

    # TODO: test_disabled_view_middleware
    def test_disabled_view_middleware(self):
        pass


@pytest.mark.django_db
class TestSigncert:

    # TODO: test_throttle_request
    def test_throttle_request(self):
        pass

    # TODO: test_validate_SAN
    def test_validate_SAN(self):
        pass

    # TODO: test_validate_template_rights
    def test_validate_template_rights(self):
        pass

    # TODO: test_create_certificate_request
    def test_create_certificate_request(self):
        pass

    # TODO: test_get_intermediary_response
    def test_get_intermediary_response(self):
        pass

    # TODO: test_send_certificate_to_mail
    def test_send_certificate_to_mail(self):
        pass

    @patch('pki_bridge.views.get_intermediary_response')
    def test_signcert(self, mock_intermediary_response, client):
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
        # content = response.content
        assert response.status_code == 200
        assert Certificate.objects.all().count() == 1
        assert CertificateRequest.objects.all().count() == 1
        assert Requester.objects.all().count() == 1


@pytest.mark.django_db
class TestViews:

    def test_listtemplates(self, client):
        response = client.get('/api/v1/listtemplates/')
        assert response.content != b''
        assert response.status_code == 200
        ps = ProjectSettings.get_solo()
        ps.update_templates_from_ca = False
        ps.save()
        Template.objects.all().delete()
        response = client.get('/api/v1/listtemplates/')
        assert response.content == b''
        assert response.status_code == 200
        ps = ProjectSettings.get_solo()
        ps.update_templates_from_ca = True
        ps.save()
        Template.objects.all().delete()
        response = client.get('/api/v1/listtemplates/')
        assert response.content != b''
        assert response.status_code == 200

    def test_pingca(self, client):
        response = client.get('/api/v1/pingca/')
        assert response.status_code == 200

    # TODO: test_run_scanner_view
    def test_run_scanner_view(self, client):
        pass

    # TODO: test_addnote
    def test_addnote(self, client):
        pass

    # TODO: test_trackurl
    def test_trackurl(self, client):
        pass

    def test_listcommands(self, client):
        response = client.get('/api/v1/listcommands/')
        assert response.status_code == 200
        response = client.post('/api/v1/listcommands/')
        assert response.status_code == 200

    def test_get_help(self, client):
        command = Command.objects.all().first().name
        response = client.get(f'/api/v1/get_help/{command}/')
        assert response.status_code == 200

    def test_getcert(self, client):
        requester = Requester.objects.create(email="andrey.mendela@leonteq.com")
        test_cert_filepath = settings.BASE_DIR / 'fixtures' / 'test_certificate.pem'
        with open(test_cert_filepath, 'r', encoding='utf-8') as cert_file:
            certificate = Certificate.objects.create(
                pem=cert_file.read()
            )
        with open('src/test_data/pki_test.csr') as f:
            certificate_request1 = CertificateRequest.objects.create(
                requester=requester,
                template="LeonteqWebSrvManualEnroll",
                domain='',
                SAN="altname1, altname2, altname3",
                csr=f,
                certificate=None,
            )
            certificate_request2 = CertificateRequest.objects.create(
                requester=requester,
                template="LeonteqWebSrvManualEnroll",
                domain='',
                SAN="altname1, altname2, altname3",
                csr=f,
                certificate=certificate,
            )
        response = client.get(f'/api/v1/getcert/{certificate_request1.id}/')
        assert response.status_code == 200
        assert response.content == b'Certificate is empty.\n'
        response = client.get(f'/api/v1/getcert/{certificate_request2.id}/')
        assert response.status_code == 200
        assert response.content != b''
        response = client.post(f'/api/v1/getcert/{certificate_request1.id}/')
        assert response.status_code == 200
        assert response.content == b'Certificate is empty.\n'
        response = client.post(f'/api/v1/getcert/{certificate_request2.id}/')
        assert response.status_code == 200
        assert response.content != b''

    def test_getcacert(self, client):
        response = client.get('/api/v1/getcacert/')
        assert response.status_code == 200
        response = client.get('/api/v1/getcacert/?cert_format=pem')
        assert response.status_code == 200
        response = client.get('/api/v1/getcacert/?cert_format=json')
        assert response.status_code == 200
        response = client.get('/api/v1/getcacert/?cert_format=text')
        assert response.status_code == 200
        response = client.post('/api/v1/getcacert/')
        assert response.status_code == 200
        response = client.post('/api/v1/getcacert/', data={'cert_format': 'pem'})
        assert response.status_code == 200
        response = client.post('/api/v1/getcacert/', data={'cert_format': 'text'})
        assert response.status_code == 200

    def test_getintermediarycert(self, client):
        response = client.get('/api/v1/getintermediarycert/')
        assert response.status_code == 200
        response = client.get('/api/v1/getintermediarycert/?cert_format=pem')
        assert response.status_code == 200
        response = client.get('/api/v1/getintermediarycert/?cert_format=json')
        assert response.status_code == 200
        response = client.get('/api/v1/getintermediarycert/?cert_format=text')
        assert response.status_code == 200
        response = client.post('/api/v1/getintermediarycert/')
        assert response.status_code == 200
        response = client.post('/api/v1/getintermediarycert/', data={'cert_format': 'pem'})
        assert response.status_code == 200
        response = client.post('/api/v1/getintermediarycert/', data={'cert_format': 'text'})
        assert response.status_code == 200

    def test_getcacertchain(self, client):
        response = client.get('/api/v1/getcacertchain/')
        assert response.status_code == 200
        response = client.get('/api/v1/getcacertchain/?cert_format=pem')
        assert response.status_code == 200
        response = client.get('/api/v1/getcacertchain/?cert_format=json')
        assert response.status_code == 200
        response = client.get('/api/v1/getcacertchain/?cert_format=text')
        assert response.status_code == 200
        response = client.post('/api/v1/getcacertchain/')
        assert response.status_code == 200
        response = client.post('/api/v1/getcacertchain/', data={'cert_format': 'pem'})
        assert response.status_code == 200
        response = client.post('/api/v1/getcacertchain/', data={'cert_format': 'text'})
        assert response.status_code == 200

    # def test_createkeyandcsr(self, client):
    #     pass

    # def test_createkeyandsign(self, client):
    #     pass

    # def test_revokecert(self, client):
    #     pass
