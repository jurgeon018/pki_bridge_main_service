from django.core.management.base import BaseCommand
from pki_bridge.management import set_domain_name



class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument(
            '-d',
            '--domain',
            type=str,
        )

    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py set_domain_name
        '''
        domain = kwargs['domain']
        set_domain_name(domain=domain)
        self.stdout.write('Domain name has been updated successfully')
