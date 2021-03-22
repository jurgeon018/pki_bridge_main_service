from django.core.management.base import BaseCommand
from pki_bridge.management import gen_readonly_group


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py gen_readonly_group
        '''
        gen_readonly_group()
        print('Readonly group has been generated successfully.')
