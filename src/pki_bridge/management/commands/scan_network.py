from django.core.management.base import BaseCommand
from pki_bridge.core.scanner import Scanner


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py scan_network
        '''
        Scanner().scan_network()
        print('Network has been scanned successfully.')
