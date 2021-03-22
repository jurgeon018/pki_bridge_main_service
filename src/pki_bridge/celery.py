import os
from celery import Celery


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pki_bridge.settings')
app = Celery('pki_bridge')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
