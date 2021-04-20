from django.core.management.base import BaseCommand
from pki_bridge.management import gen_random_data


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py gen_random_data
        '''
        gen_random_data()
        print('Random data has been generated successfully.')
