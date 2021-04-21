# Generated by Django 3.1.3 on 2021-04-21 20:24

from django.conf import settings
import django.contrib.auth.models
import django.contrib.auth.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='ProjectUser',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('email', models.EmailField(blank=True, max_length=254, null=True, unique=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
            ],
            options={
                'verbose_name': 'User',
                'verbose_name_plural': 'Users',
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='Certificate',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('pem', models.TextField()),
                ('valid_from', models.DateTimeField(blank=True, null=True)),
                ('valid_till', models.DateTimeField(blank=True, null=True)),
                ('issued_to', models.TextField(blank=True, null=True)),
                ('issuer_ou', models.TextField(blank=True, null=True)),
                ('issuer_cn', models.TextField(blank=True, null=True)),
                ('issued_o', models.TextField(blank=True, null=True)),
                ('issuer_c', models.TextField(blank=True, null=True)),
                ('issuer_o', models.TextField(blank=True, null=True)),
                ('cert_sha1', models.TextField(blank=True, null=True)),
                ('cert_sans', models.TextField(blank=True, null=True)),
                ('cert_alg', models.TextField(blank=True, null=True)),
                ('cert_ver', models.IntegerField(blank=True, null=True)),
                ('cert_sn', models.TextField(blank=True, null=True)),
                ('cert_info', models.TextField(blank=True, null=True)),
                ('cert_json', models.TextField(blank=True, null=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_certificate_created_by', to=settings.AUTH_USER_MODEL)),
                ('last_updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_certificate_last_updated_by', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Certificate',
                'verbose_name_plural': 'Certificates',
            },
        ),
        migrations.CreateModel(
            name='CertificateRequest',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('template', models.TextField()),
                ('domain', models.TextField()),
                ('SAN', models.TextField()),
                ('csr', models.TextField()),
                ('certificate', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='pki_bridge.certificate')),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_certificaterequest_created_by', to=settings.AUTH_USER_MODEL)),
                ('last_updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_certificaterequest_last_updated_by', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'CertificateRequest',
                'verbose_name_plural': 'CertificateRequests',
                'ordering': ['id'],
            },
        ),
        migrations.CreateModel(
            name='Host',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('is_active', models.BooleanField(default=True)),
                ('name', models.CharField(db_index=True, max_length=255)),
                ('contacts', models.CharField(blank=True, max_length=255, null=True)),
                ('days_to_expire', models.PositiveIntegerField(default=30)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_host_created_by', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Host',
                'verbose_name_plural': 'Hosts',
                'ordering': ['id'],
            },
        ),
        migrations.CreateModel(
            name='ProjectSettings',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('validate_templates', models.BooleanField()),
                ('enable_mail_notifications', models.BooleanField()),
                ('update_templates_from_ca', models.BooleanField()),
                ('allow_use_file_as_ldap_results', models.BooleanField()),
                ('enable_template_rights_validation', models.BooleanField()),
                ('ldap_username', models.CharField(max_length=255)),
                ('ldap_password', models.CharField(max_length=255)),
                ('days_to_expire', models.PositiveIntegerField()),
                ('scan_timeout', models.IntegerField()),
                ('hosts_per_page', models.PositiveIntegerField(blank=True, null=True)),
                ('certificates_per_page', models.PositiveIntegerField(blank=True, null=True)),
                ('reset_period', models.PositiveIntegerField(blank=True, null=True)),
                ('allowed_requests', models.PositiveIntegerField(blank=True, help_text='per {reset_period} hours for one IP-address', null=True)),
                ('ca', models.TextField()),
                ('intermediary', models.TextField()),
                ('chain', models.TextField()),
                ('scanner_secret_key', models.SlugField()),
                ('email_host', models.CharField(blank=True, default='devmail.fpprod.corp', max_length=256, null=True)),
                ('email_port', models.SmallIntegerField(blank=True, default=465, null=True)),
                ('default_from_email', models.CharField(blank=True, default='andrey.mendela@leonteq.com', max_length=256, null=True)),
                ('email_host_user', models.CharField(blank=True, max_length=256, null=True)),
                ('email_host_password', models.CharField(blank=True, max_length=256, null=True)),
                ('email_use_tls', models.BooleanField(default=False)),
                ('email_use_ssl', models.BooleanField(default=True)),
                ('fail_silently', models.BooleanField(default=False, help_text='Throw error when mail sending wasnt successful')),
                ('timeout', models.SmallIntegerField(blank=True, help_text='Timeout in seconds', null=True)),
            ],
            options={
                'verbose_name': 'ProjectSettings',
                'verbose_name_plural': 'ProjectSettings',
            },
        ),
        migrations.CreateModel(
            name='Template',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('is_active', models.BooleanField(default=True)),
                ('name', models.CharField(max_length=255, unique=True)),
                ('description', models.TextField()),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_template_created_by', to=settings.AUTH_USER_MODEL)),
                ('last_updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_template_last_updated_by', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Template',
                'verbose_name_plural': 'Templates',
            },
        ),
        migrations.CreateModel(
            name='Requester',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('email', models.CharField(max_length=255)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_requester_created_by', to=settings.AUTH_USER_MODEL)),
                ('last_updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_requester_last_updated_by', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Requester',
                'verbose_name_plural': 'Requesters',
            },
        ),
        migrations.CreateModel(
            name='Port',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.PositiveIntegerField()),
                ('is_active', models.BooleanField(default=True)),
                ('project_settings', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='pki_bridge.projectsettings')),
            ],
            options={
                'verbose_name': 'Port',
                'verbose_name_plural': 'Ports',
            },
        ),
        migrations.CreateModel(
            name='Note',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('text', models.TextField()),
                ('certificate_request', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='pki_bridge.certificaterequest')),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_note_created_by', to=settings.AUTH_USER_MODEL)),
                ('last_updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_note_last_updated_by', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Note',
                'verbose_name_plural': 'Notes',
            },
        ),
        migrations.CreateModel(
            name='Network',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('is_active', models.BooleanField(default=True)),
                ('name', models.CharField(blank=True, max_length=255, null=True)),
                ('ip', models.CharField(blank=True, max_length=255, null=True)),
                ('mask', models.CharField(blank=True, max_length=255, null=True)),
                ('vlan_id', models.CharField(blank=True, max_length=255, null=True)),
                ('contacts', models.CharField(blank=True, max_length=255, null=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_network_created_by', to=settings.AUTH_USER_MODEL)),
                ('last_updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_network_last_updated_by', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Network',
                'verbose_name_plural': 'Network',
                'unique_together': {('ip', 'mask')},
            },
        ),
        migrations.CreateModel(
            name='HostScan',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('port', models.IntegerField(blank=True, null=True)),
                ('error_message', models.TextField(blank=True, null=True)),
                ('certificate', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='pki_bridge.certificate')),
                ('host', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='scans', to='pki_bridge.host')),
            ],
            options={
                'verbose_name': 'Host scan',
                'verbose_name_plural': 'Hosts scans',
            },
        ),
        migrations.AddField(
            model_name='host',
            name='last_scan',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='last_host', to='pki_bridge.hostscan'),
        ),
        migrations.AddField(
            model_name='host',
            name='last_updated_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_host_last_updated_by', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='host',
            name='network',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='hosts', to='pki_bridge.network'),
        ),
        migrations.CreateModel(
            name='Command',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('is_active', models.BooleanField(default=True)),
                ('name', models.CharField(max_length=255)),
                ('url', models.URLField()),
                ('description', models.TextField()),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_command_created_by', to=settings.AUTH_USER_MODEL)),
                ('last_updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='pki_bridge_command_last_updated_by', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Command',
                'verbose_name_plural': 'Commands',
            },
        ),
        migrations.CreateModel(
            name='CertificateRequestScan',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('error_message', models.TextField(blank=True, null=True)),
                ('certificate_request', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='scans', to='pki_bridge.certificaterequest')),
            ],
            options={
                'verbose_name': 'Certificate request scan',
                'verbose_name_plural': 'Certificate request scans',
            },
        ),
        migrations.AddField(
            model_name='certificaterequest',
            name='requester',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='pki_bridge.requester'),
        ),
        migrations.CreateModel(
            name='AllowedCN',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('is_active', models.BooleanField(default=True)),
                ('project_settings', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='pki_bridge.projectsettings')),
            ],
            options={
                'verbose_name': 'Allowed CN',
                'verbose_name_plural': 'Allowed CNs',
            },
        ),
        migrations.AddField(
            model_name='projectuser',
            name='templates',
            field=models.ManyToManyField(blank=True, to='pki_bridge.Template'),
        ),
        migrations.AddField(
            model_name='projectuser',
            name='user_permissions',
            field=models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions'),
        ),
    ]
