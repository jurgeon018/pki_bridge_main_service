from django.conf import settings

import logging

from pki_bridge.models import (
    Template,
)


BASE_DIR = settings.BASE_DIR
logger = logging.getLogger(__name__)
