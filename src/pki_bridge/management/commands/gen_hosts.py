from django.core.management.base import BaseCommand
from pki_bridge.models import ProjectSettings
from pki_bridge.management import gen_hosts


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py gen_hosts
        '''
        gen_hosts()
        print('Hosts has been updated successfully.')
