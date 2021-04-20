import pytest
from pki_bridge.tests.utils import get_pem
from pki_bridge.models import (
    ProjectSettings,
    Command,
    ProjectUser,
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
from django.urls import reverse



app_admin_names = [
    "projectsettings",
    "command",
    "projectuser",
    "network",
    "host",
    "certificaterequestscan",
    "hostscan",
    "template",
    "requester",
    "note",
    "certificaterequest",
    "certificate",
]


@pytest.fixture
def prepare_db():
    # ProjectSettings.objects.all().delete()
    # Command.objects.all().delete()
    # ProjectUser.objects.all().delete()
    # Network.objects.all().delete()
    # Host.objects.all().delete()
    # CertificateRequestScan.objects.all().delete()
    # HostScan.objects.all().delete()
    # Template.objects.all().delete()
    # Requester.objects.all().delete()
    # Note.objects.all().delete()
    # CertificateRequest.objects.all().delete()
    # Certificate.objects.all().delete()
    ProjectSettings.get_solo()
    Command.objects.create(
        name='value',
    )
    ProjectUser.objects.create(
        username='username',
    )
    Network.objects.create()
    Host.objects.create(name='value')
    CertificateRequestScan.objects.create()
    HostScan.objects.create()
    Template.objects.create(name='template')
    Requester.objects.create(email='email')
    Note.objects.create(text='value')
    CertificateRequest.objects.create()
    Certificate.objects.create(pem=get_pem())
        

def get_response_status_codes(urls, client):
    statuse_codes = []
    for url in urls:
        response = client.get(url)
        code = response.status_code
        statuse_codes.append(code)
        # print('func_name:', response.resolver_match.func.__name__, '|| status_code:', code)
    return statuse_codes


@pytest.mark.django_db
def test_admin_changelist_views_on_get(client):
    ProjectUser.objects.create_superuser('pki_bridge_admin', 'pki_bridge_admin@gmail.com', 'pki_bridge_admin')
    client.login(username='pki_bridge_admin', password='pki_bridge_admin')
    urls = [reverse(f'admin:pki_bridge_{app_admin_name}_changelist') for app_admin_name in app_admin_names]
    success_statuses = get_response_status_codes(urls, client)
    client.logout()
    redirect_statuses = get_response_status_codes(urls, client)
    success_statuses = list(set(success_statuses))
    redirect_statuses = list(set(redirect_statuses))
    assert len(success_statuses) == 1
    assert len(success_statuses) == 1
    assert success_statuses[0] == 200
    assert redirect_statuses[0] == 302


def get_read_urls():
    read_urls = []
    for app_admin_name in app_admin_names:
        read_url = reverse(f'admin:pki_bridge_{app_admin_name}_change', args=[1])
        read_urls.append(read_url)
    return read_urls


@pytest.mark.parametrize(
    'read_url',
    get_read_urls()
)
@pytest.mark.django_db
def test_admin_change_views_200(read_url, client, prepare_db):
    ProjectUser.objects.create_superuser('pki_bridge_admin', 'pki_bridge_admin@gmail.com', 'pki_bridge_admin')
    client.login(username='pki_bridge_admin', password='pki_bridge_admin')
    response = client.get(read_url)
    assert response.status_code == 200
    client.logout()
    response = client.get(read_url)
    assert response.status_code == 302


@pytest.mark.django_db
class TestProjectSettingsAdmin:
    pass


@pytest.mark.django_db
class TestCommandAdmin:
    pass


@pytest.mark.django_db
class TestProjectUserAdmin:
    pass


@pytest.mark.django_db
class TestNetworkAdmin:
    pass


@pytest.mark.django_db
class TestHostAdmin:
    pass


@pytest.mark.django_db
class TestCertificateRequestScanAdmin:
    pass


@pytest.mark.django_db
class TestHostScanAdmin:
    pass


@pytest.mark.django_db
class TestTemplateAdmin:
    pass


@pytest.mark.django_db
class TestRequesterAdmin:
    pass


@pytest.mark.django_db
class TestNoteAdmin:
    pass


@pytest.mark.django_db
class TestCertificateRequestAdmin:
    pass


@pytest.mark.django_db
class TestCertificateAdmin:
    pass
