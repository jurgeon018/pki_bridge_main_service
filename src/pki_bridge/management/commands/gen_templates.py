from django.core.management.base import BaseCommand
from pki_bridge.management import update_templates


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py gen_templates
        '''
        update_templates()
        print('Templates has been generated successfully.')
