from django.core.management.base import BaseCommand
from pki_bridge.core.scanner import Scanner


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py scan_network
        '''
        scanner = Scanner()
        scanner.verbosity = 2
        scanner.scan_network()
        print('Network has been scanned successfully.')
