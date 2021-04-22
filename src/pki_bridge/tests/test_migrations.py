import pytest
from django_test_migrations.plan import all_migrations, nodes_to_tuples


@pytest.mark.django_db()
def test_0002_data_migrations(migrator):

    old_state = migrator.apply_initial_migration(('pki_bridge', None))
    with pytest.raises(LookupError):
        old_state.apps.get_model('pki_bridge', 'Template')
    with pytest.raises(LookupError):
        old_state.apps.get_model('pki_bridge', 'Template')
    with pytest.raises(LookupError):
        old_state.apps.get_model('pki_bridge', 'Command')
    with pytest.raises(LookupError):
        old_state.apps.get_model('pki_bridge', 'Network')
    with pytest.raises(LookupError):
        old_state.apps.get_model('pki_bridge', 'Host')
    with pytest.raises(LookupError):
        old_state.apps.get_model('pki_bridge', 'ProjectSettings')
    with pytest.raises(LookupError):
        old_state.apps.get_model('pki_bridge', 'ProjectUser')
    with pytest.raises(LookupError):
        old_state.apps.get_model('pki_bridge', 'AllowedCN')
    with pytest.raises(LookupError):
        old_state.apps.get_model('pki_bridge', 'Port')
    with pytest.raises(LookupError):
        old_state.apps.get_model('sites', 'Site')

    new_state = migrator.apply_tested_migration(('pki_bridge', '0001_initial'))

    ContentType = new_state.apps.get_model('contenttypes', 'ContentType')
    assert ContentType.objects.all().count() == 0
    Template = new_state.apps.get_model('pki_bridge', 'Template')
    assert Template.objects.all().count() == 0
    Group = new_state.apps.get_model('auth', 'Group')
    assert Group.objects.all().count() == 0
    Permission = new_state.apps.get_model('auth', 'Permission')
    assert Permission.objects.all().count() == 0
    Command = new_state.apps.get_model('pki_bridge', 'Command')
    assert Command.objects.all().count() == 0
    Network = new_state.apps.get_model('pki_bridge', 'Network')
    assert Network.objects.all().count() == 0
    Host = new_state.apps.get_model('pki_bridge', 'Host')
    assert Host.objects.all().count() == 0
    ProjectSettings = new_state.apps.get_model('pki_bridge', 'ProjectSettings')
    assert ProjectSettings.objects.all().count() == 0
    ProjectUser = new_state.apps.get_model('pki_bridge', 'ProjectUser')
    assert ProjectUser.objects.all().count() == 0
    AllowedCN = new_state.apps.get_model('pki_bridge', 'AllowedCN')
    assert AllowedCN.objects.all().count() == 0
    Port = new_state.apps.get_model('pki_bridge', 'Port')
    assert Port.objects.all().count() == 0
    with pytest.raises(LookupError):
        new_state.apps.get_model('sites', 'Site')

    new_state = migrator.apply_tested_migration(('pki_bridge', '0002_data_migrations'))

    ContentType = new_state.apps.get_model('contenttypes', 'ContentType')
    assert ContentType.objects.all().count() != 0
    Template = new_state.apps.get_model('pki_bridge', 'Template')
    assert Template.objects.all().count() != 0
    Group = new_state.apps.get_model('auth', 'Group')
    assert Group.objects.all().count() != 0
    Permission = new_state.apps.get_model('auth', 'Permission')
    assert Permission.objects.all().count() != 0
    Command = new_state.apps.get_model('pki_bridge', 'Command')
    assert Command.objects.all().count() != 0
    Network = new_state.apps.get_model('pki_bridge', 'Network')
    assert Network.objects.all().count() != 0
    Host = new_state.apps.get_model('pki_bridge', 'Host')
    assert Host.objects.all().count() != 0
    ProjectSettings = new_state.apps.get_model('pki_bridge', 'ProjectSettings')
    assert ProjectSettings.objects.all().count() != 0
    ProjectUser = new_state.apps.get_model('pki_bridge', 'ProjectUser')
    assert ProjectUser.objects.all().count() != 0
    AllowedCN = new_state.apps.get_model('pki_bridge', 'AllowedCN')
    assert AllowedCN.objects.all().count() != 0
    Port = new_state.apps.get_model('pki_bridge', 'Port')
    assert Port.objects.all().count() != 0
    Site = new_state.apps.get_model('sites', 'Site')
    assert Site.objects.all().count() != 0






# https://github.com/wemake-services/django-test-migrations
# https://stackoverflow.com/questions/44003620/how-do-i-run-tests-against-a-django-data-migration
# https://www.caktusgroup.com/blog/2016/02/02/writing-unit-tests-django-migrations/
# https://micknelson.wordpress.com/2013/03/01/testing-django-migrations/#comments
# from django_test_migrations.migrator import Migrator
# @pytest.mark.django_db()
# def test_0002_data_migrations_2():
#     migrator = Migrator(database='default')

#     old_state = migrator.before(('pki_bridge', '0001_initial'))
#     Template = old_state.apps.get_model('pki_bridge', 'Template')

#     # One instance will be `clean`, the other won't be:
#     Template.objects.create(name='a')
#     Template.objects.create(name='a b')

#     assert Template.objects.count() == 2
#     assert Template.objects.filter(name__isnull=False).count() == 2

#     new_state = migrator.after(('pki_bridge', '0003_auto_20191119_2125'))
#     Template = new_state.apps.get_model('pki_bridge', 'Template')

#     assert Template.objects.count() == 2
#     # One instance is clean, the other is not:
#     assert Template.objects.filter(is_clean=True).count() == 1
#     assert Template.objects.filter(is_clean=False).count() == 1

# @pytest.mark.django_db()
# def test_migrations_order():
#     apps = [
#         'pki_bridge',
#     ]
#     main_migrations = all_migrations('default', apps)
#     assert nodes_to_tuples(main_migrations) == [
#         ('pki_bridge', '0001_initial'),
#         ('pki_bridge', '0002_data_migrations'),
#     ]