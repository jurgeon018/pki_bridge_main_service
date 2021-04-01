import subprocess
from django.urls import reverse
import logging


logger = logging.getLogger(__name__)

def set_openssl_version():
    openssl_version = get_openssl_version()
    msg = f'Version of openssl is: "{openssl_version}"'
    logger.info(msg)


def get_openssl_version():
    try:
        args = [
            'openssl',
            'version',
        ]
        openssl_version = run(args).decode('utf-8')
    except Exception as e:
        openssl_version = None
    return openssl_version


def run(args):
    if isinstance(args, str):
        args = args.split(' ')
    p = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output, _ = p.communicate()
    if not p.returncode == 0:
        raise Exception(f'returncode is 0. args: {args}')
    # return output
    return output.decode()


def get_admin_url(obj):
    admin_url = reverse(f'admin:{obj._meta.app_label}_{obj._meta.model_name}_change', args=[obj.id])
    return admin_url
