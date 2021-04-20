from unittest.mock import patch

import pytest
from django.conf import settings
from pki_bridge.models import Certificate
from pki_bridge.models import CertificateRequest
from pki_bridge.models import Command
from pki_bridge.models import Host
from pki_bridge.models import Note
from pki_bridge.models import ProjectSettings
from pki_bridge.models import ProjectUser
from pki_bridge.models import Requester
from pki_bridge.models import Template
from pki_bridge.views import build_mail_message
from pki_bridge.views import create_certificate_request
from pki_bridge.views import get_intermediary_response
from pki_bridge.views import requests
from pki_bridge.views import send_certificate_to_mail
from pki_bridge.views import throttle_request
from pki_bridge.views import validate_SAN
from pki_bridge.views import validate_template_rights


WINDOWS_URL = settings.WINDOWS_URL
TEST_CERT_FILEPATH = settings.TEST_CERT_FILEPATH
TEST_CSR_FILEPATH = settings.TEST_CSR_FILEPATH


def mocked_response(url):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    with open(TEST_CERT_FILEPATH) as f:
        certificate = f.read()
    if url == f"{WINDOWS_URL}/submit":
        return MockResponse({"certificate": certificate}, 200)


class TestMiddlewares:

    # TODO: test_disabled_view_middleware
    def test_disabled_view_middleware(self):
        pass


@pytest.mark.django_db
class TestSigncert:
    def test_throttle_request(self, client):
        project_settings = ProjectSettings.get_solo()
        requester_email = "andrey.mendela@leonteq.com"
        requester = Requester.objects.create(
            email=requester_email,
        )
        for i in range(1, 10 + 1):
            CertificateRequest.objects.create(requester=requester)

        project_settings.allowed_requests = 0
        project_settings.reset_period = 0
        project_settings.save()
        result = throttle_request(requester_email)
        assert result is None

        project_settings.allowed_requests = 20
        project_settings.reset_period = 1
        project_settings.save()
        result = throttle_request(requester_email)
        assert result is None

        project_settings.allowed_requests = 5
        project_settings.reset_period = 1
        project_settings.save()
        result = throttle_request(requester_email)
        assert result is not None

        data = {
            "requester": requester_email,
        }
        response = client.post("/api/v1/signcert/", data=data)
        assert response.status_code == 403

    def test_validate_SAN(self):
        strings = [
            " ",
            "fdsasdf  sdfda",
            "fdsasdf sd1 sdf",
            "fdsasdf sd1  sdf",
            "fdsasdf sd1   sdf",
            "fdsasdf sdf     sdfda",
            "  fdsasdf sdf     sdfda",
            "  fdsasdf sdf     sdfda  ",
        ]
        for string in strings:
            result = validate_SAN(string)
            assert " " not in result

    def test_validate_template_rights(self, client):
        project_settings = ProjectSettings.get_solo()
        project_settings.enable_template_rights_validation = False
        project_settings.save()
        template1 = Template.objects.create(name="template1")
        unallowed_template = "template2"
        password = "123123123"
        requester_email = "user@leonteq.com"
        user = ProjectUser.objects.create(username="x", email=requester_email)
        user.set_password(password)
        user.templates.add(template1)
        user.save()

        assert validate_template_rights(requester_email=None, password=None, template=None) is None

        project_settings.enable_template_rights_validation = True
        project_settings.save()

        assert validate_template_rights(requester_email="blablabla", password=None, template=None) == "User does not exist.\n"
        assert (
            validate_template_rights(
                requester_email=requester_email,
                password="blabla",
                template=None,
            )
            == "Password is incorrect\n"
        )
        assert user.check_password(password) is True
        assert validate_template_rights(requester_email=requester_email, password=password, template=unallowed_template) == "You do not have rights to use this template.\n"
        assert (
            validate_template_rights(
                requester_email=requester_email,
                password=password,
                template="template1",
            )
            is None
        )

        with patch("pki_bridge.views.throttle_request") as mocked_throttle_request:
            mocked_throttle_request.return_value = None
            data = {
                "requester": requester_email,
                "password": password,
                "template": unallowed_template,
            }
            response = client.post("/api/v1/signcert/", data=data)
            assert response.status_code == 400
            assert response.content == b"You do not have rights to use this template.\n"

    @patch("pki_bridge.views.entry_is_in_ldap", return_value=True)
    @patch("pki_bridge.views.throttle_request", return_value=None)
    @patch("pki_bridge.views.validate_template_rights", return_value=None)
    @patch("pki_bridge.views.send_certificate_to_mail", return_value=None)
    @patch("pki_bridge.views.get_intermediary_response", return_value=None)
    def test_create_certificate_request(
        self,
        mocked_get_intermediary_response,
        mocked_send_certificate_to_mail,
        mocked_validate_template_rights,
        mocked_throttle_request,
        mocked_entry_is_in_ldap,
        client,
    ):
        assert CertificateRequest.objects.all().count() == 0
        assert Requester.objects.all().count() == 0
        assert Note.objects.all().count() == 0
        assert Certificate.objects.all().count() == 0
        with open(TEST_CERT_FILEPATH) as pem:
            pem = pem.read()
        note_text = "ssdfsdfsdf"
        requester_email = "requester_email"
        template = "template"
        Template.objects.create(name=template)
        domain = "domain"
        SAN = "SAN"
        csr = "csr"
        query = {
            "enable_sending_certificate_to_mail": "false",
            "note": note_text,
        }
        result = create_certificate_request(pem, requester_email, template, domain, SAN, csr, query)
        certificate_requests = CertificateRequest.objects.all()
        certificate_request = certificate_requests.first()
        notes = Note.objects.all()
        note = notes.first()
        assert Requester.objects.all().count() == 1
        assert certificate_requests.count() == 1
        assert result == certificate_request
        assert certificate_request.requester.email == requester_email
        assert certificate_request.template == template
        assert certificate_request.domain == domain
        assert certificate_request.SAN == SAN
        assert certificate_request.csr == csr
        assert certificate_request.certificate.pem == pem
        assert Note.objects.all().count() == 1
        assert note.text == note_text
        assert note.certificate_request == certificate_request

        mocked_send_certificate_to_mail.assert_not_called()

        query = {"enable_sending_certificate_to_mail": "true"}
        result = create_certificate_request(pem, requester_email, template, domain, SAN, csr, query)
        mocked_send_certificate_to_mail.assert_called_with(requester_email, result)

        query = {}
        result = create_certificate_request(pem, requester_email, template, domain, SAN, csr, query)
        assert Note.objects.all().count() == 1
        password = "123123123"
        project_user = ProjectUser.objects.create(username="x", email=requester_email)
        project_user.set_password(password)
        project_user.save()
        mocked_get_intermediary_response.return_value = {"certificate": "INVALID CERTIFICATE"}
        with open(TEST_CSR_FILEPATH) as f:
            data = {
                "requester": requester_email,
                "password": password,
                "template": template,
                "domain": domain,
                "SAN": SAN,
                "csr": f,
            }
            response = client.post("/api/v1/signcert/", data=data)
        assert response.status_code == 500
        mocked_get_intermediary_response.return_value = {
            "INVALID_KEY": "FSDFSDF",
        }
        with open(TEST_CSR_FILEPATH) as f:
            data = {
                "requester": requester_email,
                "password": password,
                "template": template,
                "domain": domain,
                "SAN": SAN,
                "csr": f,
            }
            response = client.post("/api/v1/signcert/", data=data)
        assert response.status_code == 500
        with open(TEST_CERT_FILEPATH) as f:
            mocked_get_intermediary_response.return_value = {
                "certificate": f.read(),
            }
        with open(TEST_CSR_FILEPATH) as f:
            data = {
                "requester": requester_email,
                "password": password,
                "template": template,
                "domain": domain,
                "SAN": SAN,
                "csr": f,
            }
            response = client.post("/api/v1/signcert/", data=data)
        assert response.status_code == 200

    # # @patch('pki_bridge.views.requests.post')
    # @patch.object(requests, "post")
    # def test_get_intermediary_response(self, mocked_requests):
    #     # test if returns dict(response.json())
    #     url = f"{WINDOWS_URL}/submit"
    #     response = mocked_response(url)
    #     mocked_requests.return_value = response
    #     csr = "csr"
    #     domain = "domain"
    #     template = "template"
    #     SAN = "SAN"
    #     result = get_intermediary_response(csr, domain, template, SAN)
    #     assert isinstance(result, dict)
    #     # test if called with
    #     data = {
    #         "secret_key": settings.WINDOWS_SECRET_KEY,
    #         "csr": csr,
    #         "domain": domain,
    #         "template": template,
    #         "san": SAN,
    #     }
    #     mocked_requests.assert_called_with(url, verify=False, json=data)
    #     # test if returns message when ConnectionError occurs
    #     error_message = "msg"
    #     mocked_requests.side_effect = requests.exceptions.ConnectionError(error_message)
    #     result = get_intermediary_response(csr, domain, template, SAN)
    #     assert result == f"Cannot connect to intermediary.\n{error_message}.\n"
    #     # test if returns message when Exception occurs
    #     error_message = "msg"
    #     mocked_requests.side_effect = Exception(error_message)
    #     result = get_intermediary_response(csr, domain, template, SAN)
    #     assert result == f"Error occured. {error_message}. \n"

    @patch("pki_bridge.views.send_mail")
    def test_send_certificate_to_mail(self, mocked_send_mail):
        requester_email = ""
        with open(TEST_CSR_FILEPATH) as f:
            csr = f.read()
        with open(TEST_CERT_FILEPATH) as f:
            pem = f.read()
        certificate = Certificate.objects.create(pem=pem)
        certificate_request = CertificateRequest.objects.create(
            certificate=certificate,
            csr=csr,
        )
        result = send_certificate_to_mail(requester_email, certificate_request)
        assert result is None
        mocked_send_mail.assert_called_with(
            subject=f"Certificate request #{certificate_request.id}",
            message=build_mail_message(certificate_request),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[
                requester_email,
            ],
            fail_silently=False,
        )

    @patch("pki_bridge.views.get_intermediary_response")
    def test_signcert(self, mock_intermediary_response, client):
        assert Certificate.objects.all().count() == 0
        assert Requester.objects.all().count() == 0
        assert CertificateRequest.objects.all().count() == 0
        with open(TEST_CERT_FILEPATH, encoding="utf-8") as cert_file:
            mock_intermediary_response.return_value = {"certificate": cert_file.read()}
        with open(TEST_CSR_FILEPATH) as f:
            data = {
                "requester": "andrey.mendela@leonteq.com",
                "template": "LeonteqWebSrvManualEnroll",
                "SAN": "altname1, altname2, altname3",
                "note": "note test example",
                "env": "env",
                "certformat": "pem",
                "csr": f,
            }
            response = client.post("/api/v1/signcert/", data=data)
        assert response.status_code == 200
        assert Certificate.objects.all().count() == 1
        assert CertificateRequest.objects.all().count() == 1
        assert Requester.objects.all().count() == 1


@pytest.mark.django_db
class TestViews:
    def test_listtemplates(self, client):
        response = client.get("/api/v1/listtemplates/")
        assert response.content != b""
        assert response.status_code == 200
        ps = ProjectSettings.get_solo()
        ps.update_templates_from_ca = False
        ps.save()
        Template.objects.all().delete()
        response = client.get("/api/v1/listtemplates/")
        assert response.content == b""
        assert response.status_code == 200
        ps = ProjectSettings.get_solo()
        ps.update_templates_from_ca = True
        ps.save()
        Template.objects.all().delete()
        response = client.get("/api/v1/listtemplates/")
        assert response.content != b""
        assert response.status_code == 200

    def test_pingca(self, client):
        response = client.get("/api/v1/pingca/")
        assert response.status_code == 200

    # TODO: test_run_scanner_view
    def test_run_scanner_view(self, client):
        pass

    def test_addnote(self, client):
        certificate_request = CertificateRequest.objects.create()
        id = certificate_request.id
        note_text = "fdsasdf"
        data = {"note": note_text}
        response = client.post(f"/api/v1/addnote/{id}/", data=data)
        assert response.content == b"Note was successfully created.\n"
        data = {"note": note_text}
        assert Note.objects.all().count() == 1
        assert Note.objects.all().first().text == note_text
        assert Note.objects.all().first().certificate_request == certificate_request
        response = client.post("/api/v1/addnote/100/", data=data)
        assert response.content.decode("utf-8") == "Note wasn't created because certificate_request with id 100 does not exist.\n"
        assert Note.objects.all().count() == 1
        assert Note.objects.all().first().text == note_text
        assert Note.objects.all().first().certificate_request == certificate_request

    def test_trackurl(self, client):
        Host.objects.all().delete()
        name = "https://www.google.com"
        contacts = "contact@gmail.com"
        data = {
            "url": name,
            "contacts": contacts,
        }
        response = client.post("/api/v1/trackurl/", data=data)
        assert Host.objects.all().count() == 1
        assert Host.objects.all().first().name == name
        assert Host.objects.all().first().contacts == contacts
        assert response.content.decode("utf-8") == "Network device has been created successfully.\n"
        name = "https://www.google.com"
        contacts = "contact2@gmail.com"
        data = {
            "url": name,
            "contacts": contacts,
        }
        response = client.post("/api/v1/trackurl/", data=data)
        assert response.content.decode("utf-8") == "Network device with this name already exists.\n"
        assert Host.objects.all().count() == 1
        assert Host.objects.all().first().name == name
        assert Host.objects.all().first().contacts == contacts

    def test_listcommands(self, client):
        response = client.get("/api/v1/listcommands/")
        assert response.status_code == 200
        response = client.post("/api/v1/listcommands/")
        assert response.status_code == 200

    def test_get_help(self, client):
        command = Command.objects.all().first().name
        response = client.get(f"/api/v1/get_help/{command}/")
        assert response.status_code == 200

    def test_getcert(self, client):
        requester = Requester.objects.create(email="andrey.mendela@leonteq.com")
        TEST_CERT_FILEPATH = settings.BASE_DIR / "fixtures" / "test_certificate.pem"
        with open(TEST_CERT_FILEPATH, encoding="utf-8") as cert_file:
            certificate = Certificate.objects.create(pem=cert_file.read())
        with open(TEST_CSR_FILEPATH) as f:
            certificate_request1 = CertificateRequest.objects.create(
                requester=requester,
                template="LeonteqWebSrvManualEnroll",
                domain="",
                SAN="altname1, altname2, altname3",
                csr=f,
                certificate=None,
            )
            certificate_request2 = CertificateRequest.objects.create(
                requester=requester,
                template="LeonteqWebSrvManualEnroll",
                domain="",
                SAN="altname1, altname2, altname3",
                csr=f,
                certificate=certificate,
            )
        response = client.get(f"/api/v1/getcert/{certificate_request1.id}/")
        assert response.status_code == 200
        assert response.content == b"Certificate is empty.\n"
        response = client.get(f"/api/v1/getcert/{certificate_request2.id}/")
        assert response.status_code == 200
        assert response.content != b""
        response = client.post(f"/api/v1/getcert/{certificate_request1.id}/")
        assert response.status_code == 200
        assert response.content == b"Certificate is empty.\n"
        response = client.post(f"/api/v1/getcert/{certificate_request2.id}/")
        assert response.status_code == 200
        assert response.content != b""

    def test_getcacert(self, client):
        response = client.get("/api/v1/getcacert/")
        assert response.status_code == 200
        response = client.get("/api/v1/getcacert/?cert_format=pem")
        assert response.status_code == 200
        response = client.get("/api/v1/getcacert/?cert_format=json")
        assert response.status_code == 200
        response = client.get("/api/v1/getcacert/?cert_format=text")
        assert response.status_code == 200
        response = client.post("/api/v1/getcacert/")
        assert response.status_code == 200
        response = client.post("/api/v1/getcacert/", data={"cert_format": "pem"})
        assert response.status_code == 200
        response = client.post("/api/v1/getcacert/", data={"cert_format": "text"})
        assert response.status_code == 200

    def test_getintermediarycert(self, client):
        response = client.get("/api/v1/getintermediarycert/")
        assert response.status_code == 200
        response = client.get("/api/v1/getintermediarycert/?cert_format=pem")
        assert response.status_code == 200
        response = client.get("/api/v1/getintermediarycert/?cert_format=json")
        assert response.status_code == 200
        response = client.get("/api/v1/getintermediarycert/?cert_format=text")
        assert response.status_code == 200
        response = client.post("/api/v1/getintermediarycert/")
        assert response.status_code == 200
        response = client.post("/api/v1/getintermediarycert/", data={"cert_format": "pem"})
        assert response.status_code == 200
        response = client.post("/api/v1/getintermediarycert/", data={"cert_format": "text"})
        assert response.status_code == 200

    def test_getcacertchain(self, client):
        response = client.get("/api/v1/getcacertchain/")
        assert response.status_code == 200
        response = client.get("/api/v1/getcacertchain/?cert_format=pem")
        assert response.status_code == 200
        response = client.get("/api/v1/getcacertchain/?cert_format=json")
        assert response.status_code == 200
        response = client.get("/api/v1/getcacertchain/?cert_format=text")
        assert response.status_code == 200
        response = client.post("/api/v1/getcacertchain/")
        assert response.status_code == 200
        response = client.post("/api/v1/getcacertchain/", data={"cert_format": "pem"})
        assert response.status_code == 200
        response = client.post("/api/v1/getcacertchain/", data={"cert_format": "text"})
        assert response.status_code == 200

    # def test_createkeyandcsr(self, client):
    #     pass

    # def test_createkeyandsign(self, client):
    #     pass

    # def test_revokecert(self, client):
    #     pass
