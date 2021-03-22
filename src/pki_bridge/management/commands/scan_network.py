from django.core.management.base import BaseCommand
from pki_bridge.core.scanner import scan_network


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py scan_network
        '''
        scan_network()
        print('Network has been scanned successfully.')
