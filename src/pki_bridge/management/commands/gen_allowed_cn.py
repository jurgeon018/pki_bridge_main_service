from django.core.management.base import BaseCommand
from pki_bridge.management import gen_allowed_cn


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py gen_allowed_cn
        '''
        gen_allowed_cn()
        print('Allowed CNs has been generated successfully.')

