from django.core.management.base import BaseCommand
from pki_bridge.models import ProjectSettings


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        '''
        python3 src/manage.py gen_settings
        '''
        ProjectSettings().get_solo().update_settings()
        print('Settings has been updated successfully.')