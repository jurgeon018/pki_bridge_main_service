import pytest
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from pki_bridge.models import (
    Command,
    ProjectUser,
    ProjectSettings,
    AllowedCN,
    Port,
    Network,
    Host,
    CertificateRequestScan,
    HostScan,
    Template,
    Requester,
    Note,
    CertificateRequest,
    Certificate,
)
from pki_bridge.core.converter import Converter
from pki_bridge.core.utils import make_timezone_aware
from pki_bridge.conf import db_settings

from datetime import datetime


@pytest.mark.django_db
class TestCertificate:
    test_cert_filepath = settings.BASE_DIR / 'fixtures' / 'test_certificate.pem'

    def test_str(self):
        assert type(str(Certificate.objects.all().first())) == str

    def read_pem(self):
        with open(self.test_cert_filepath, 'r') as f:
            pem = f.read()
        return pem

    def create_certificate(self):
        pem = self.read_pem()
        certificate = Certificate(pem=pem)
        certificate.save()
        return certificate

    def populate(self):
        pem = self.read_pem()
        certificate = self.create_certificate()
        pyopenssl_cert = Converter(pem, 'pem', 'pyopenssl_cert').cert
        pyopenssl_json_cert = Converter(pyopenssl_cert, 'pyopenssl_cert', 'json').cert
        attributes = [
            'issued_to',
            'issuer_ou',
            'issuer_cn',
            'issued_o',
            'issuer_c',
            'issuer_o',
            'cert_sha1',
            'cert_sans',
            'cert_alg',
            'cert_ver',
            'cert_sn',
        ]
        for attribute in attributes:
            assert getattr(certificate, attribute) == pyopenssl_json_cert.get(attribute)
        dt_format = '%Y-%m-%d'
        valid_from = pyopenssl_json_cert['valid_from']
        valid_till = pyopenssl_json_cert['valid_till']
        valid_from = datetime.strptime(valid_from, dt_format)
        valid_till = datetime.strptime(valid_till, dt_format)
        valid_from = make_timezone_aware(valid_from)
        valid_till = make_timezone_aware(valid_till)
        assert certificate.valid_from == valid_from
        assert certificate.valid_till == valid_till

    def test_save(self):
        self.populate()

    def test_is_from_different_ca(self):
        AllowedCN.objects.all().delete()
        AllowedCN.objects.create(name='allowed_cn')
        certificate = self.create_certificate()
        certificate.issuer_cn = 'allowed_cn'
        certificate.save()
        assert certificate.is_from_different_ca is False
        certificate.issuer_cn = 'unallowed_cn'
        certificate.save()
        assert certificate.is_from_different_ca is True

    def test_is_self_signed(self):
        certificate = self.create_certificate()
        assert type(certificate.is_self_signed) is bool

    def test_valid_days_to_expire(self):
        certificate = self.create_certificate()
        days = (certificate.valid_till - timezone.now()).days
        assert type(days) is int

    def test_validity_days(self):
        certificate = self.create_certificate()
        days = (certificate.valid_till - certificate.valid_from).days
        assert type(days) is int

    def test_is_expired(self):
        certificate = self.create_certificate()
        expired = certificate.is_expired
        assert type(expired) is bool

    def test_cert_info(self):
        certificate = self.create_certificate()
        pem = certificate.pem
        converter = Converter(pem, 'pem', 'text')
        cert = converter.cert
        assert certificate.cert_info == cert

    def test_cert_json(self):
        certificate = self.create_certificate()
        pem = certificate.pem
        converter = Converter(pem, 'pem', 'json')
        cert = converter.cert
        assert certificate.cert_json == cert


@pytest.mark.django_db
class TestProjectSettings:

    def test_ports(self):
        ports = Port.objects.filter(is_active=True).values_list('name', flat=True)
        assert set(db_settings.ports) == set(ports)

    def test_clean(self):
        project_settings = ProjectSettings.get_solo()
        project_settings.email_use_ssl = True
        project_settings.email_use_tls = True
        with pytest.raises(ValidationError):
            project_settings.clean()

    def check_project_settings(self, project_settings):
        fields = ProjectSettings._meta.fields
        excluded_fields = [
            'id',
            'fail_silently',
            'timeout',
        ]
        for field in fields:
            if field.name in excluded_fields:
                continue
            assert getattr(project_settings, field.name) == getattr(settings, field.name.upper())

    def test_save(self):
        project_settings = ProjectSettings.get_solo()
        project_settings.save()
        self.check_project_settings(project_settings)

    def test_update_settings(self):
        project_settings = ProjectSettings.get_solo()
        project_settings.update_settings()
        self.check_project_settings(project_settings)

    def test_str(self):
        assert type(str(ProjectSettings.objects.all().first())) == str


@pytest.mark.django_db
class TestAllowedCN:

    def test_save(self):
        allowedCN = AllowedCN.objects.create(
            name="bla",
        )
        assert allowedCN.project_settings is not None

    def test_str(self):
        assert type(str(AllowedCN.objects.all().first())) == str


@pytest.mark.django_db
class TestPort:

    def test_save(self):
        port = Port.objects.create(
            name=8000,
        )
        assert port.project_settings is not None

    def test_str(self):
        assert type(str(Port.objects.all().first())) == str


@pytest.mark.django_db
class TestNetwork:
    def test_str(self):
        assert type(str(Network.objects.all().first())) == str


@pytest.mark.django_db
class TestHost:
    def test_str(self):
        assert type(str(Host.objects.all().first())) == str


@pytest.mark.django_db
class TestCertificateRequestScan:
    def test_str(self):
        assert type(str(CertificateRequestScan.objects.all().first())) == str


@pytest.mark.django_db
class TestHostScan:
    def test_str(self):
        assert type(str(HostScan.objects.all().first())) == str


@pytest.mark.django_db
class TestTemplate:
    def test_str(self):
        assert type(str(Template.objects.all().first())) == str


@pytest.mark.django_db
class TestRequester:
    def test_str(self):
        assert type(str(Requester.objects.all().first())) == str


@pytest.mark.django_db
class TestNote:
    def test_str(self):
        assert type(str(Note.objects.all().first())) == str


@pytest.mark.django_db
class TestCertificateRequest:
    def test_str(self):
        assert type(str(CertificateRequest.objects.all().first())) == str


@pytest.mark.django_db
class TestCommand:
    def test_str(self):
        assert type(str(Command.objects.all().first())) == str


@pytest.mark.django_db
class TestProjectUser:
    def test_str(self):
        assert type(str(ProjectUser.objects.all().first())) == str
