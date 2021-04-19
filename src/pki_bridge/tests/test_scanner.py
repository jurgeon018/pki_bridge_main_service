import socket
from unittest.mock import patch

import pytest
from django.conf import settings
from OpenSSL.SSL import Error
from OpenSSL.SSL import SysCallError
from pki_bridge.core.converter import (
    Converter,
)
from pki_bridge.core.scanner import Scanner
from pki_bridge.core.scanner import SSL
from pki_bridge.core.utils import get_obj_admin_link
from pki_bridge.models import Certificate
from pki_bridge.models import CertificateRequest
from pki_bridge.models import CertificateRequestScan
from pki_bridge.models import Host
from pki_bridge.models import HostScan
from pki_bridge.models import ProjectSettings


@pytest.mark.django_db
class TestDbCertificateScanner:
    @pytest.mark.parametrize(
        "certificates_per_page,certificates_amount,expected_page_scan_results_len",
        [
            [5, 9, 2],
            [6, 9, 2],
            [7, 9, 2],
            [8, 9, 2],
            [9, 9, 1],
            [4, 8, 2],
            [4, 9, 3],
            [1, 9, 9],
            [None, 1, 1],
            [None, 2, 1],
            [None, 9, 1],
            [None, 100, 1],
        ],
    )
    @patch("pki_bridge.core.scanner.DbCertificatesScanner.scan_certificates_page")
    def test_scan_db_certificates(
        self,
        scan_certificates_page_mock,
        certificates_per_page,
        certificates_amount,
        expected_page_scan_results_len,
    ):
        CertificateRequest.objects.all().delete()
        Certificate.objects.all().delete()
        CertificateRequestScan.objects.all().delete()
        scan_certificates_page_mock.return_value = [{}]
        project_settings = ProjectSettings.get_solo()
        project_settings.certificates_per_page = certificates_per_page
        project_settings.save()
        for j in range(certificates_amount):
            with open(settings.TEST_CERT_FILEPATH) as f:
                certificate = Certificate.objects.create(
                    pem=f.read(),
                )
            CertificateRequest.objects.create(
                certificate=certificate,
            )
        page_scan_results = Scanner().scan_db_certificates()
        assert len(page_scan_results) == expected_page_scan_results_len
        for certreq in CertificateRequest.objects.all():
            CertificateRequestScan.objects.create(certificate_request=certreq)
        page_scan_results = Scanner().scan_db_certificates()
        # checks if exclude works
        assert len(page_scan_results) == 1

    @patch("pki_bridge.core.scanner.DbCertificatesScanner.scan_db_certficate")
    def test_scan_certificates_page(
        self,
        scan_db_certficate_mock,
    ):
        return_value = ""
        scan_db_certficate_mock.return_value = return_value
        csrs_amount = 10
        for _ in range(csrs_amount):
            CertificateRequest.objects.create()
        certificates_page = CertificateRequest.objects.all()
        result = Scanner().scan_certificates_page(certificates_page)
        assert len(result) == csrs_amount
        assert set(result) == {return_value}

    @patch("pki_bridge.core.scanner.DbCertificatesScanner.mail_requesters")
    def test_scan_db_certificate(
        self,
        mail_requesters_mock,
    ):
        CertificateRequestScan.objects.all().delete()
        assert CertificateRequestScan.objects.all().count() == 0
        with open(settings.TEST_CERT_FILEPATH) as f:
            pem = f.read()
        unvalid_pem = "unvalid_pem"
        # checks if doesnt try to create certificate request scan when certificate is None
        certificate_request = CertificateRequest.objects.create()
        result = Scanner().scan_db_certficate(certificate_request)
        assert CertificateRequestScan.objects.all().count() == 0
        assert result is None
        # checks if certificate request scan is created
        CertificateRequestScan.objects.all().delete()
        certificate = Certificate.objects.create(pem=pem)
        certificate_request = CertificateRequest.objects.create(certificate=certificate)
        result = Scanner().scan_db_certficate(certificate_request)
        assert result == {}
        assert CertificateRequestScan.objects.all().count() == 1
        assert CertificateRequestScan.objects.all().first().error_message is None
        # check if creates error message
        CertificateRequestScan.objects.all().delete()
        certificate = Certificate.objects.create(pem=pem)
        certificate.pem = unvalid_pem
        certificate.save()
        certificate_request = CertificateRequest.objects.create(certificate=certificate)
        result = Scanner().scan_db_certficate(certificate_request)
        # # assert result is None
        assert CertificateRequestScan.objects.all().count() == 1
        assert CertificateRequestScan.objects.all().first().error_message is not None

    @patch("pki_bridge.core.scanner.DbCertificatesScanner.notify_about_expired")
    @patch("pki_bridge.core.scanner.DbCertificatesScanner.notify_about_almost_expired")
    @patch("pki_bridge.core.scanner.DbCertificatesScanner.notify_about_self_signed")
    @patch("pki_bridge.core.scanner.DbCertificatesScanner.notify_about_different_ca")
    def test_mail_requesters(
        self,
        mocked_notify_about_different_ca,
        mocked_notify_about_self_signed,
        mocked_notify_about_almost_expired,
        mocked_notify_about_expired,
    ):
        print(mocked_notify_about_different_ca)
        mocked_notify_about_different_ca.return_value = None
        mocked_notify_about_self_signed.return_value = None
        mocked_notify_about_almost_expired.return_value = None
        mocked_notify_about_expired.return_value = None
        with open(settings.TEST_CERT_FILEPATH) as f:
            pem = f.read()
        certificate = Certificate.objects.create(pem=pem)
        certificate_request = CertificateRequest.objects.create(certificate=certificate)
        certificate_request_scan = CertificateRequestScan.objects.create(
            certificate_request=certificate_request,
        )
        link = get_obj_admin_link(certificate_request_scan)

        result = Scanner().mail_requesters(certificate_request_scan)

        assert result is None

        if certificate.is_expired:
            mocked_notify_about_expired.assert_called_with(certificate_request_scan, certificate_request, certificate, link)
        else:
            mocked_notify_about_expired.assert_not_called()

        if certificate.valid_days_to_expire < ProjectSettings.get_solo().days_to_expire:
            mocked_notify_about_almost_expired.assert_called_with(certificate_request_scan, certificate_request, certificate, link)
        else:
            mocked_notify_about_almost_expired.assert_not_called()

        if certificate.is_self_signed:
            mocked_notify_about_self_signed.assert_called_with(certificate_request_scan, certificate_request, certificate, link)
        else:
            mocked_notify_about_self_signed.assert_not_called()

        if certificate.is_from_different_ca:
            mocked_notify_about_different_ca.assert_called_with(certificate_request_scan, certificate_request, certificate, link)
        else:
            mocked_notify_about_different_ca.assert_not_called()

    # # TODO test_notify_about_expired
    # def test_notify_about_expired(self):
    #     pass

    # # TODO test_notify_about_almost_expired
    # def test_notify_about_almost_expired(self):
    #     pass

    # # TODO test_notify_about_self_signed
    # def test_notify_about_self_signed(self):
    #     pass

    # # TODO test_notify_about_different_ca
    # def test_notify_about_different_ca(self):
    #     pass

    def test_analyze_scan_results(self):
        pass


@pytest.mark.django_db
class TestNetworkScanner:
    @pytest.mark.parametrize(
        "hosts_per_page,hosts_amount,expected_page_scan_results_len",
        [
            [3, 20, 7],
            [1, 20, 20],
            [2, 20, 10],
            [3, 20, 7],
            [4, 20, 5],
            [5, 20, 4],
            [6, 20, 4],
            [7, 20, 3],
            [8, 20, 3],
            [9, 20, 3],
            [10, 20, 2],
            [11, 20, 2],
            [19, 20, 2],
            [20, 20, 1],
            [None, 1, 1],
            [None, 2, 1],
            [None, 9, 1],
            [None, 100, 1],
        ],
    )
    @patch("pki_bridge.core.scanner.NetworkScanner.scan_hosts_page")
    def test_scan_hosts(
        self,
        scan_hosts_page_mock,
        hosts_per_page,
        hosts_amount,
        expected_page_scan_results_len,
    ):
        Host.objects.all().delete()
        Certificate.objects.all().delete()
        HostScan.objects.all().delete()
        scan_hosts_page_mock.return_value = [{}]
        project_settings = ProjectSettings.get_solo()
        project_settings.hosts_per_page = hosts_per_page
        project_settings.save()
        for j in range(hosts_amount):
            Host.objects.create(
                name=f"host{j}",
            )
        page_scan_results = Scanner().scan_hosts()
        assert len(page_scan_results) == expected_page_scan_results_len

    @patch("pki_bridge.core.scanner.NetworkScanner.host_exists")
    @patch("pki_bridge.core.scanner.NetworkScanner.scan_host")
    def test_scan_hosts_page(self, scan_host_mock, mock_host_exists):
        Host.objects.all().delete()
        mock_host_exists.return_value = True
        ports = ProjectSettings().get_solo().ports
        return_value = ""
        scan_host_mock.return_value = return_value
        hosts_amount = 4
        for i in range(hosts_amount):
            Host.objects.create(name=f"host{i}")
        hosts_page = Host.objects.all()
        result = Scanner().scan_hosts_page(hosts_page)
        assert len(result) == hosts_amount * len(ports)
        assert set(result) == {return_value}

    @patch("pki_bridge.core.scanner.NetworkScanner.get_cert_of_host")
    @patch("pki_bridge.core.scanner.NetworkScanner.get_pem_of_host")
    @patch("pki_bridge.core.scanner.NetworkScanner.mail_admins")
    def test_scan_host(self, mocked_mail_admins, mocked_get_pem_of_host, mocked_get_cert_of_host):
        assert HostScan.objects.all().count() == 0
        assert Certificate.objects.all().count() == 0

        with open(settings.TEST_CERT_FILEPATH) as f:
            pem = f.read()
        with open(settings.TEST_CERT2_FILEPATH) as f:
            pem2 = f.read()
        pyopenssl_cert = Converter(pem, "pem", "pyopenssl_cert").cert
        hostname, port = "google.com", 8000
        host = Host.objects.create(name=hostname)

        project_settings = ProjectSettings().get_solo()

        mocked_get_cert_of_host.return_value = pyopenssl_cert
        mocked_get_pem_of_host.return_value = pem
        project_settings.enable_mail_notifications = False
        project_settings.save()
        result = Scanner().scan_host(host, port)
        assert result is None
        assert Certificate.objects.all().count() == 1
        assert HostScan.objects.all().count() == 1
        assert HostScan.objects.all().first().certificate.pem == pem
        mocked_get_cert_of_host.assert_called_with(host.name, port)
        mocked_get_pem_of_host.assert_called_with(host.name, port)
        mocked_mail_admins.assert_not_called()

        project_settings.enable_mail_notifications = True
        project_settings.save()
        result = Scanner().scan_host(host, port)
        assert Certificate.objects.all().count() == 2
        assert HostScan.objects.all().count() == 2
        mocked_get_cert_of_host.assert_called_with(host.name, port)
        mocked_get_pem_of_host.assert_called_with(host.name, port)
        mocked_mail_admins.assert_called_with(host, port, Certificate.objects.all().last(), HostScan.objects.all().last())

        mocked_pyopenssl_cert = "not OpenSSL.crypto.X509 instance"
        mocked_get_cert_of_host.return_value = mocked_pyopenssl_cert
        result = Scanner().scan_host(host, port)
        assert isinstance(result, dict)
        assert Certificate.objects.all().count() == 2
        assert HostScan.objects.all().count() == 3
        msg = f"{host}:{port} didnt return certificate."
        msg += f"Error: {mocked_pyopenssl_cert}({type(mocked_pyopenssl_cert)})"
        assert result["error_message"] == msg
        assert HostScan.objects.all().last().error_message == msg

        mocked_get_cert_of_host.return_value = pyopenssl_cert
        mocked_get_pem_of_host.return_value = pem2
        result = Scanner().scan_host(host, port)
        assert isinstance(result, dict)
        assert Certificate.objects.all().count() == 2
        assert HostScan.objects.all().count() == 4
        msg = f"'openssl s_client -connect {host.name}:{port}' "
        msg += "and 'SSL.Connection.get_peer_certificate()' "
        msg += "returted different pem certificates."
        assert result["error_message"] == msg
        assert HostScan.objects.all().last().error_message == msg

    @patch("pki_bridge.core.scanner.NetworkScanner.mail_admins_about_expired")
    @patch("pki_bridge.core.scanner.NetworkScanner.mail_admins_about_almost_expired")
    @patch("pki_bridge.core.scanner.NetworkScanner.mail_admins_about_self_signed")
    @patch("pki_bridge.core.scanner.NetworkScanner.mail_admins_about_different_ca")
    def test_mail_admins(
        self,
        mail_admins_about_different_ca_mock,
        mail_admins_about_self_signed_mock,
        mail_admins_about_almost_expired_mock,
        mail_admins_about_expired_mock,
    ):
        host = Host.objects.create(name="host")
        port = 8000
        with open(settings.TEST_CERT_FILEPATH) as f:
            pem = f.read()
        certificate = Certificate.objects.create(pem=pem)
        scan = HostScan.objects.create(host=host)
        link = get_obj_admin_link(scan)

        result = Scanner().mail_admins(host, port, certificate, scan)
        assert result is None

        if certificate.is_from_different_ca:
            mail_admins_about_different_ca_mock.assert_called_once_with(host, port, certificate, scan, link)
        else:
            mail_admins_about_different_ca_mock.assert_not_called()

        if certificate.is_self_signed:
            mail_admins_about_self_signed_mock.assert_called_once_with(host, port, certificate, scan, link)
        else:
            mail_admins_about_self_signed_mock.assert_not_called()

        if certificate.valid_days_to_expire < host.days_to_expire:
            mail_admins_about_almost_expired_mock.assert_called_once_with(host, port, certificate, scan, link)
        else:
            mail_admins_about_almost_expired_mock.assert_not_called()

        if certificate.is_expired:
            mail_admins_about_expired_mock.assert_called_once_with(host, port, certificate, scan, link)
        else:
            mail_admins_about_expired_mock.assert_not_called()

    # # TODO test_mail_admins_about_expired
    # def test_mail_admins_about_expired(self):
    #     result = Scanner().mail_admins_about_expired()
    #     # assert result == result

    # # TODO test_mail_admins_about_almost_expired
    # def test_mail_admins_about_almost_expired(self):
    #     result = Scanner().mail_admins_about_almost_expired()
    #     # assert result == result

    # # TODO test_mail_admins_about_self_signed
    # def test_mail_admins_about_self_signed(self):
    #     result = Scanner().mail_admins_about_self_signed()
    #     # assert result == result

    # # TODO test_mail_admins_about_different_ca
    # def test_mail_admins_about_different_ca(self):
    #     result = Scanner().mail_admins_about_different_ca()
    #     # assert result == result

    @patch("pki_bridge.core.scanner.logger")
    @patch("pki_bridge.core.scanner.socket.gethostbyname")
    def test_host_exists(
        self,
        mocked_gethostbyname,
        mocked_logger,
    ):
        host = Host.objects.create(name="google.com")

        mocked_gethostbyname.side_effect = socket.gaierror("error")
        result = Scanner().host_exists(host)
        assert result is False

        mocked_gethostbyname.side_effect = None
        result = Scanner().host_exists(host)
        assert result is True

    @patch("pki_bridge.core.scanner.run")
    def test_get_pem_of_host(self, mocked_run):
        host, port = "google.com", 8000
        args = [
            "openssl",
            "s_client",
            "-connect",
            f"{host}:{port}",
        ]
        pem = "test pem"
        expected_result = ""
        expected_result += "-----BEGIN CERTIFICATE-----\n"
        expected_result += pem
        expected_result += "\n-----END CERTIFICATE-----"
        mocked_run.return_value = pem
        result = Scanner().get_pem_of_host(host, port)
        assert result == expected_result
        mocked_run.assert_called_with(args)

    @patch("pki_bridge.core.scanner.socket")
    @patch.object(SSL, "Connection")
    @patch.object(SSL, "Context")
    def test_get_cert_of_host(
        self,
        mocked_Context,
        mocked_Connection,
        mocked_socket,
    ):
        host, port = "host", 8000

        mocked_Connection.return_value.do_handshake.side_effect = SysCallError("e")
        result = Scanner().get_cert_of_host(host, port)
        # TODO v2: test if socket.socket.connect was called with right arguments
        # mocked_socket.return_value.socket.return_value.connect.assert_called_with((host, int(port)))
        mocked_Connection.return_value.get_peer_certificate.assert_not_called()
        assert isinstance(result, SysCallError)
        assert result, "e"

        mocked_Connection.return_value.do_handshake.side_effect = Error("e")
        result = Scanner().get_cert_of_host(host, port)
        # TODO v2: test if socket.socket.connect was called with right arguments
        # mocked_socket.return_value.socket.return_value.connect.assert_called_with((host, int(port)))
        mocked_Connection.return_value.get_peer_certificate.assert_not_called()
        assert isinstance(result, Error)
        assert result, "e"

        mocked_Connection.return_value.do_handshake.side_effect = None
        mocked_Connection.return_value.do_handshake.side_effect = None
        mocked_Connection.return_value.get_peer_certificate.return_value = "cert"
        result = Scanner().get_cert_of_host(host, port)
        mocked_Connection.return_value.set_tlsext_host_name.assert_called_with(host.encode())
        mocked_Connection.return_value.set_connect_state.assert_called_with()
        assert result == "cert"

        # TODO v2: test if socket.timeout error catching works ok
        # TODO v2: test if ConnectionRefusedError catching works ok
        # import socket
        # mocked_socket.return_value.connect.side_effect = socket.timeout('timeout error')
        # assert result == 'timeout error'

    @pytest.mark.parametrize(
        "string,expected_result",
        [
            ["https://www.google.com", "www.google.com"],
            ["http://www.google.com", "www.google.com"],
            ["http:///www.google.com", "www.google.com"],
            ["https:///www.google.com", "www.google.com"],
            ["https:///www.google.com/", "www.google.com"],
            ["https:////google.com//", "google.com"],
            ["https:////google.com///", "google.com"],
        ],
    )
    def test_filter_hostname(self, string, expected_result):
        result = Scanner().filter_hostname(string)
        assert result == expected_result

    def test_analyze_ssl(self):
        pass

    def test_analyze_scan_results(self):
        # result = Scanner().analyze_scan_results()
        pass


class TestScanner:
    @patch.object(Scanner, "scan_db_certificates")
    @patch.object(Scanner, "scan_hosts")
    def test_scan_network(
        self,
        scan_hosts,
        scan_db_certificates,
    ):
        Scanner().scan_network()
        scan_hosts.assert_called_with()
        scan_db_certificates.assert_called_with()
