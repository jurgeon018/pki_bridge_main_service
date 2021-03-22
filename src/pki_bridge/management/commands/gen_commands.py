from django.core.management.base import BaseCommand
from pki_bridge.management import gen_commands


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py gen_commands
        '''
        gen_commands()
        print('Commands has been generated successfully.')
