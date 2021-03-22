from django.core.management.base import BaseCommand
from pki_bridge.management import gen_networks


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py gen_networks
        '''
        gen_networks()
        print('Networks has been generated successfully.')
