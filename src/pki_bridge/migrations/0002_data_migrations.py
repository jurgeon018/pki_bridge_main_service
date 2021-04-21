from django.conf import settings
from django.db import migrations
from django.contrib.contenttypes.management import create_contenttypes
from django.contrib.auth.management import create_permissions

from pki_bridge.management import (
    gen_readonly_group,
    gen_user,
    gen_commands,
    update_templates,
    gen_networks,
    gen_hosts,
    gen_allowed_cn,
    gen_ports,
)
from pki_bridge.models.settings import ProjectSettings


def gen_contenttypes(apps):
    app_config = apps.get_app_config('pki_bridge')
    app_config.models_module = app_config.models_module or True
    create_contenttypes(app_config, verbosity=1)
    create_permissions(app_config, verbosity=1)

    app_config = apps.get_app_config('auth')
    app_config.models_module = app_config.models_module or True
    create_contenttypes(app_config, verbosity=1)
    create_permissions(app_config, verbosity=1)

    app_config = apps.get_app_config('contenttypes')
    app_config.models_module = app_config.models_module or True
    create_contenttypes(app_config, verbosity=1)
    create_permissions(app_config, verbosity=1)


def migrate_readonly_group(apps, schema_editor):
    gen_contenttypes(apps)
    Group = apps.get_model('auth', 'Group')
    ContentType = apps.get_model('contenttypes', 'ContentType')
    Permission = apps.get_model('auth', 'Permission')
    gen_readonly_group(
        Group=Group,
        ContentType=ContentType,
        Permission=Permission,
    )


def migrate_commands(apps, schema_editor):
    Command = apps.get_model('pki_bridge', 'Command')
    gen_commands(Command=Command)


def migrate_templates(apps, schema_editor):
    Template = apps.get_model('pki_bridge', 'Template')
    update_templates(Template=Template)


def migrate_networks(apps, schema_editor):
    Network = apps.get_model('pki_bridge', 'Network')
    gen_networks(Network=Network)


def migrate_hosts(apps, schema_editor):
    print('migrate_hosts')
    Host = apps.get_model('pki_bridge', 'Host')
    Network = apps.get_model('pki_bridge', 'Network')
    gen_hosts(Host=Host, Network=Network)


def migrate_settings(apps, schema_editor):
    # ProjectSettings = apps.get_model('pki_bridge', 'ProjectSettings')
    settings = ProjectSettings.get_solo()
    # settings.update_settings()
    # settings.save()
    print(settings.validate_templates)


def migrate_user(apps, schema_editor):
    ProjectUser = apps.get_model('pki_bridge', 'ProjectUser')
    gen_user(ProjectUser=ProjectUser)


def migrate_allowed_cn(apps, schema_editor):
    AllowedCN = apps.get_model('pki_bridge', 'AllowedCN')
    gen_allowed_cn(AllowedCN=AllowedCN)


def migrate_ports(apps, schema_editor):
    Port = apps.get_model('pki_bridge', 'Port')
    gen_ports(Port=Port)


def migrate_domain_name(apps, schema_editor):
    domain = settings.DOMAIN
    Site = apps.get_model('sites', 'Site')
    Site.objects.all().delete()
    Site.objects.create(domain=domain, name='webapi domain')


class Migration(migrations.Migration):

    dependencies = [
        ('pki_bridge', '0001_initial'),
        ('sites', '0002_alter_domain_unique'),
    ]

    operations = [
        migrations.RunPython(migrate_readonly_group),
        migrations.RunPython(migrate_commands),
        migrations.RunPython(migrate_templates),
        migrations.RunPython(migrate_networks),
        migrations.RunPython(migrate_hosts),
        migrations.RunPython(migrate_settings),
        migrations.RunPython(migrate_allowed_cn),
        migrations.RunPython(migrate_ports),
        migrations.RunPython(migrate_user),
        migrations.RunPython(migrate_domain_name),
    ]
