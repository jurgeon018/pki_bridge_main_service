from django.core.management.base import BaseCommand
from pki_bridge.core.scanner import Scanner
from pki_bridge.models import (
    Host,
    ProjectSettings,
)
from django.core.mail import send_mail
from django.core import mail

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        host = Host.objects.filter(name='10.30.111.15').first()
        port = 8083
        scanner = Scanner()
        scanner.verbosity = 2
        # result = scanner.scan_host(host, port)
        # print(result)
        # scanner.scan_network()
      
        # send_mail(
        #     subject='subject',
        #     message='message',
        #     from_email=ProjectSettings.get_solo().default_from_email,
        #     recipient_list=[
        #         # 'menan@leonteq.com',
        #         'andrey.mendela@leonteq.com',
        #     ],
        #     fail_silently=False,
        # )
