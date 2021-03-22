from django.core.management.base import BaseCommand
from pki_bridge.management import gen_user


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py gen_user
        '''
        gen_user()
        print('User has been generated successfully.')
