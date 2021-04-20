from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Group, Permission
from django.contrib.sites.models import Site
from django.contrib.auth.hashers import make_password

from decouple import config
import json
import logging
import ipaddress
import re
import requests

from pki_bridge.models import (
    Command,
    Template,
    Host,
    Network,
    ProjectUser,
    AllowedCN,
    Port,
)


BASE_DIR = settings.BASE_DIR


logger = logging.getLogger(__name__)


def gen_readonly_group(
    Group=Group,
    ContentType=ContentType,
    Permission=Permission,
):
    new_group, _ = Group.objects.get_or_create(name='readonly')
    for ct in ContentType.objects.all():
        permissions = Permission.objects.filter(content_type=ct)
        for permission in permissions:
            if permission.codename.startswith('view'):
                new_group.permissions.add(permission)


def gen_user(
    ProjectUser=ProjectUser,
):
    users_json = [
        {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'admin69018',
        },
        {
            'username': 'andrey.mendela',
            'email': 'andrey.mendela@leonteq.com',
            'password': 'admin69018',
        },
    ]
    for user_json in users_json:
        ProjectUser.objects.create(
            username=user_json['username'],
            email=user_json['email'],
            password=make_password(user_json['password']),
            is_staff=True,
            is_active=True,
            is_superuser=True,
        )


def update_templates(
    Template=Template,
):
    WINDOWS_SCHEMA = config('WINDOWS_SCHEMA')
    WINDOWS_HOST = config('WINDOWS_HOST')
    WINDOWS_PORT = config('WINDOWS_PORT')
    WINDOWS_URL = f'{WINDOWS_SCHEMA}://{WINDOWS_HOST}:{WINDOWS_PORT}'

    try:
        url = f'{WINDOWS_URL}/get_templates'
        results = requests.get(url)
        results = results.json()
        results = results['results']
    except Exception:
        path = BASE_DIR / 'fixtures' / 'templates.txt'
        with open(path) as f:
            results = f.readlines()
    for result in results:
        if result == '':
            continue
        splitted = result.split(':')
        name = splitted[0].strip()
        description = splitted[-1].strip()
        template, _ = Template.objects.get_or_create(
            name=name,
        )
        template.description = description
        template.save()


def gen_commands(
    Command=Command,
):
    path = BASE_DIR / 'fixtures' / 'commands.json'
    with open(path) as f:
        commands = json.load(f)
    for c in commands:
        name = c['name']
        description = c['description']
        allowed_requests = c['allowed_requests']
        reset_period = c['reset_period']
        url = c['url']
        command, _ = Command.objects.get_or_create(
            name=name,
        )
        command.description = description
        command.url = url
        command.allowed_requests = allowed_requests
        command.reset_period = reset_period
        command.save()


def gen_networks_dict():

    def get_mask(ip, raw_network_line):
        splitted_raw_network_line = raw_network_line.split(ip)
        mask = splitted_raw_network_line[-1]
        mask = mask[1:3]
        return mask

    def get_name(ip, raw_network_line):
        name = "..."
        return name

    def get_vlan_id(ip, raw_network_line):
        vlan_id = "..."
        return vlan_id

    path = BASE_DIR / 'fixtures' / 'vlans.txt'
    with open(path, 'r') as f:
        raw_networks = f.read()
    raw_network_lines = raw_networks.split('\n')
    networks = []
    for raw_network_line in raw_network_lines:
        ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', raw_network_line)
        if not ips:
            continue
        if 'DMZ' in raw_network_line:
            continue
        ip = ips[0]
        mask = get_mask(ip, raw_network_line)
        name = get_name(ip, raw_network_line)
        vlan_id = get_vlan_id(ip, raw_network_line)
        network = f'{ip}/{mask}'
        try:
            net4 = ipaddress.ip_network(network)
        except ValueError:
            continue
        hosts = []
        for host in net4.hosts():
            hosts.append({
                'host': format(host),
            })
        networks.append({
            'name': name,
            'vlan_id': vlan_id,
            "network": network,
            'ip': ip,
            'mask': mask,
            'hosts_amount': len(hosts),
            'hosts': hosts,
        })
        # print(f'{network}: {len(hosts)}')
    return networks


def gen_networks_json():
    networks = gen_networks_dict()
    path = BASE_DIR / 'fixtures' / 'networks.json'
    with open(path, 'w') as f:
        json.dump(networks, f, indent=4)


def gen_networks(
    Network=Network,
):
    Network.objects.all().delete()
    path = BASE_DIR / 'fixtures' / 'networks.json'
    with open(path) as f:
        networks = json.load(f)
    contacts = settings.DEFAULT_CONTACTS_FOR_NOTIFICATIONS
    for i, json_network in enumerate(networks):
        # print(f'Network {i+1} of {len(networks)}')
        if not Network.objects.filter(
            ip=json_network['ip'],
            mask=json_network['mask'],
        ).exists():
            Network.objects.create(
                name=json_network['name'],
                ip=json_network['ip'],
                mask=json_network['mask'],
                vlan_id=json_network['vlan_id'],
                contacts=contacts
            )
        else:
            pass
            # print(json_network['ip'])


def gen_hosts(
    Host=Host,
    Network=Network,
):
    Host.objects.all().delete()
    hosts = []

    scan_test = 1
    # scan_test = 0
    scan_real = 1
    # scan_real = 0

    # test hosts
    if scan_test:
        path = BASE_DIR / 'fixtures' / 'hosts.json'
        with open(path, 'r') as f:
            json_hosts = json.load(f)
        for i, json_host in enumerate(json_hosts):
            # print(f'json host {i+1} of {len(json_hosts)}')
            hosts.append(Host(**{
                "network": None,
                "name": json_host['host'],
                "contacts": json_host['contacts'],
            }))
    # real hosts
    if scan_real:
        path = BASE_DIR / 'fixtures' / 'networks.json'
        with open(path, 'r') as f:
            json_networks = json.load(f)
        for i, json_network in enumerate(json_networks):
            # print(f'Network {i+1} of {len(json_networks)}')
            network = Network.objects.get(
                ip=json_network['ip'],
                mask=json_network['mask'],
            )
            for j, json_host in enumerate(json_network['hosts']):
                # print(f"Host {j+1} of {len(json_network['hosts'])} of network {i+1}")
                # print("json_host: ", json_host)
                hosts.append(Host(
                    name=json_host['host'],
                    network=network,
                    contacts=network.contacts,
                ))
    if hosts:
        Host.objects.bulk_create(hosts)


def gen_allowed_cn(
    AllowedCN=AllowedCN,
):
    AllowedCN.objects.all().delete()
    cns = settings.ALLOWED_CNS
    for cn in cns:
        AllowedCN.objects.create(
            name=cn,
        )


def gen_ports(
    Port=Port,
):
    Port.objects.all().delete()
    ports = settings.PORTS
    for port in ports:
        Port.objects.create(
            name=port
        )


def set_domain_name(
    domain=None,
    Site=Site,
):
    site = Site.objects.get_current()
    site.domain = domain
    site.name = domain
    site.save()


def gen_random_data():
    from pki_bridge.models import (
        Certificate,
        CertificateRequest,
        CertificateRequestScan,
        Requester,
        Note,
        HostScan,
    )
    CertificateRequestScan.objects.all().delete()
    CertificateRequest.objects.all().delete()
    Certificate.objects.all().delete()
    HostScan.objects.all().delete()
    Requester.objects.all().delete()
    Note.objects.all().delete()
    try:
        # gen_user()
        ProjectUser.objects.create_superuser(username='admin', password='admin')
    except:
        pass
    update_templates()
    gen_commands()
    gen_networks_dict()
    gen_networks_json()
    gen_networks()
    gen_hosts()
    gen_allowed_cn()
    gen_ports()
    import random
    from pki_bridge.tests.utils import get_pem
    for i in range(10):
        Requester.objects.create(email=f'email{i}')
    for i in range(100):
        Certificate.objects.create(pem=get_pem())
    for certificate in Certificate.objects.all():
        CertificateRequest.objects.create(
            csr='fdsasdf',
            domain=random.choice(['domain1', 'domain2', 'domain3']),
            requester=random.choice(Requester.objects.all()),
            SAN=random.choice(['SAN1', 'SAN2', 'SAN3']),
            template=random.choice(['template1', 'template2', 'template3', 'template4']),
            certificate=certificate,
        )
    for certificate_request in CertificateRequest.objects.all():
        CertificateRequestScan.objects.create(
            certificate_request=certificate_request,
            error_message=random.choice(['msg1', 'msg2', 'msg3', None, None, None, None, None, None, None]),
        )
    for certificate_request in CertificateRequest.objects.all():
        for i in range(random.randint(1, 5)):
            Note.objects.create(
                text=f'text{i}',
                certificate_request=certificate_request,
            )
    for i in range(200):
        HostScan.objects.create(
            host=random.choice(Host.objects.all()),
            port=random.choice(Port.objects.all()).name,
            error_message=random.choice(['msg1', 'msg2', 'msg3', None, None, None, None, None, None, None]),
            certificate=random.choice(Certificate.objects.all()),
        )
