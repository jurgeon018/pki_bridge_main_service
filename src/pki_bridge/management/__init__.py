from os import name
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Group, Permission

import json
import logging
import ipaddress
import re

from pki_bridge.core.utils import (
    run,
)
from pki_bridge.models import (
    Command,
    Template,
    Host,
    Network,
    ProjectUser,
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
    user = ProjectUser.objects.create(
        username='admin',
        email='admin@example.com',
    )
    user.set_password('admin')
    user.is_staff = True
    user.is_active = True
    user.is_superuser = True
    user.save()


def update_templates(
    Template=Template,
        ):
    try:
        command = r'certutil -config "CHVIRPKIPRD103.fpprod.corp\Leonteq Class 3 Issuing CA" -CATemplates'
        certutil_msg = 'CertUtil: -CATemplates command completed successfully.'
        results = run(command)
        results = results.decode('utf-8')
        results = results.replace(certutil_msg, '')
        results = results.split('\n')
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
        except ValueError as e:
            print(e)
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
        print(f'{network}: {len(hosts)}')
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
    for i, json_network in enumerate(networks):
        print(f'{i+1} of {len(networks)}')
        if not Network.objects.filter(
            ip=json_network['ip'],
            mask=json_network['mask'],
        ).exists():
            Network.objects.create(
                name=json_network['name'],
                ip=json_network['ip'],
                mask=json_network['mask'],
                vlan_id=json_network['vlan_id'],
            )
        else:
            print(json_network['ip'])


def gen_hosts(
    Host=Host,
    Network=Network,
        ):
    Host.objects.all().delete()
    hosts = []
    path = BASE_DIR / 'fixtures' / 'hosts.json'
    with open(path, 'r') as f:
        json_hosts = json.load(f)
    for i, json_host in enumerate(json_hosts):
        # print(json_host)
        print(f'{i+1} of {len(json_hosts)}')
        hosts.append(Host(**{
            "network": None,
            "host": json_host['host'],
            "contacts": json_host['contacts'],
        }))
        
    path = BASE_DIR / 'fixtures' / 'networks.json'
    with open(path, 'r') as f:
        json_networks = json.load(f)
    for i, json_network in enumerate(json_networks):
        # print(json_network)
        print(f'{i+1} of {len(json_networks)}')
        network = Network.objects.get(
            ip=json_network['ip'],
            mask=json_network['mask'],
        )
        for i, json_host in enumerate(json_network['hosts']):
            hosts.append(Host(
                host=json_host['host'],
                network=network,
                contacts=network.contacts,
            ))
    Host.objects.bulk_create(hosts)
