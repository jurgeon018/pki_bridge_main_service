from django.core.management.base import BaseCommand
from pki_bridge.management import gen_networks_json


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py gen_networks_json
        '''
        gen_networks_json()
        print('Networks json has been generated successfully.')
