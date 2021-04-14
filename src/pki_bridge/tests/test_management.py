import pytest
import os
from pki_bridge.models import (
    AllowedCN,
)


@pytest.mark.django_db
def test_management():
    AllowedCN.objects.all().delete()
    assert AllowedCN.objects.all().count() == 0
    command = 'python3 src/manage.py gen_allowed_cn'
    os.system(command)
    print(AllowedCN.objects.all())
    assert AllowedCN.objects.all().count() != 0
