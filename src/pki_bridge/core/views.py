from django.conf import settings

import logging

from pki_bridge.models import (
    Template,
)


BASE_DIR = settings.BASE_DIR
logger = logging.getLogger(__name__)



def build_templates_string():
    tempates = Template.objects.all()
    templates_string = ''
    for template in tempates:
        templates_string += f'{template.name}: {template.description}\n'
    return templates_string
