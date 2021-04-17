import pytest
from io import StringIO
from pki_bridge.models import (
    AllowedCN,
    Command,
    Host,
    Network,
    ProjectSettings,
    Template,
    ProjectUser,
)
from pki_bridge.management import (
    gen_allowed_cn,
    gen_commands,
    gen_hosts,
    gen_networks_json,
    gen_networks,
    gen_readonly_group,
    update_templates,
    gen_user,
    set_domain_name,
)
from django.contrib.auth.models import Group
from django.contrib.sites.models import Site
from django.core.management import call_command


def run_command(command, *args, **kwargs):
    out = StringIO()
    call_command(
        command,
        *args,
        stdout=out,
        stderr=StringIO(),
        **kwargs,
    )
    return out.getvalue()


@pytest.mark.django_db
def test_gen_allowed_cn():

    AllowedCN.objects.all().delete()
    assert AllowedCN.objects.all().count() == 0
    run_command('gen_allowed_cn')
    assert AllowedCN.objects.all().count() != 0

    AllowedCN.objects.all().delete()
    assert AllowedCN.objects.all().count() == 0
    gen_allowed_cn()
    assert AllowedCN.objects.all().count() != 0


@pytest.mark.django_db
def test_gen_commands():

    Command.objects.all().delete()
    assert Command.objects.all().count() == 0
    run_command('gen_commands')
    assert Command.objects.all().count() != 0

    Command.objects.all().delete()
    assert Command.objects.all().count() == 0
    gen_commands()
    assert Command.objects.all().count() != 0


@pytest.mark.django_db
def test_gen_hosts():

    Host.objects.all().delete()
    assert Host.objects.all().count() == 0
    run_command('gen_hosts')
    assert Host.objects.all().count() != 0

    Host.objects.all().delete()
    assert Host.objects.all().count() == 0
    gen_hosts()
    assert Host.objects.all().count() != 0


# @pytest.mark.django_db
# def test_gen_networks_json():
#     run_command('gen_networks_json')
#     gen_networks_json.objects.all().delete()
#     assert gen_networks_json.objects.all().count() == 0

#     # gen_networks_json()

#     gen_networks_json.objects.all().delete()
#     assert gen_networks_json.objects.all().count() == 0


@pytest.mark.django_db
def test_gen_networks():
    Network.objects.all().delete()
    assert Network.objects.all().count() == 0
    run_command('gen_networks')
    assert Network.objects.all().count() != 0

    Network.objects.all().delete()
    assert Network.objects.all().count() == 0
    gen_networks()
    assert Network.objects.all().count() != 0


@pytest.mark.django_db
def test_gen_readonly_group():
    Group.objects.all().delete()
    assert Group.objects.all().count() == 0
    run_command('gen_readonly_group')
    assert Group.objects.all().count() != 0

    Group.objects.all().delete()
    assert Group.objects.all().count() == 0
    gen_readonly_group()
    assert Group.objects.all().count() != 0


@pytest.mark.django_db
def test_gen_settings():
    ProjectSettings.objects.all().delete()
    assert ProjectSettings.objects.all().count() == 0
    run_command('gen_settings')
    assert ProjectSettings.objects.all().count() != 0

    ProjectSettings.objects.all().delete()
    assert ProjectSettings.objects.all().count() == 0
    ProjectSettings.get_solo().update_settings()
    assert ProjectSettings.objects.all().count() != 0


@pytest.mark.django_db
def test_gen_templates():
    Template.objects.all().delete()
    assert Template.objects.all().count() == 0
    run_command('gen_templates')
    assert Template.objects.all().count() != 0

    Template.objects.all().delete()
    assert Template.objects.all().count() == 0
    update_templates()
    assert Template.objects.all().count() != 0


@pytest.mark.django_db
def test_gen_user():
    ProjectUser.objects.all().delete()
    assert ProjectUser.objects.all().count() == 0
    run_command('gen_user')
    assert ProjectUser.objects.all().count() != 0

    ProjectUser.objects.all().delete()
    assert ProjectUser.objects.all().count() == 0
    gen_user()
    assert ProjectUser.objects.all().count() != 0


# @pytest.mark.django_db
# def test_set_domain_name():
#     run_command('set_domain_name')
#     assert Site.objects.all().count() != 0

#     set_domain_name()
#     assert Site.objects.all().count() != 0
