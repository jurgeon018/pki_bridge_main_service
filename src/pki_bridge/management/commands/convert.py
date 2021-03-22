from django.core.management.base import BaseCommand
from pki_bridge.core.convert import get_openssl_func
from pki_bridge.core.utils import run


class Command(BaseCommand):

  def add_arguments(self, parser):
    parser.add_argument(
        '-in',
        '--in',
        type=str,
        help='in path'
    )
    parser.add_argument(
        '-out',
        '--out',
        type=str,
        help='out path'
    )
    parser.add_argument(
        '-inform',
        '--inform',
        type=str,
        help='inform type'
    )
    parser.add_argument(
        '-outform',
        '--outform',
        type=str,
        help='outform type'
    )
    parser.add_argument(
        '-from',
        '--from',
        type=str,
        help='from format'
    )
    parser.add_argument(
        '-to',
        '--to',
        type=str,
        help='to format'
    )

  def handle(self, *args, **kwargs):
    '''
    python3 src/manage.py convert -from pem -in src/test_data/.pem
    python3 src/manage.py convert -from pfx -to pem -in src/test_data/certificates/chvird42prd01/cert.p12 -out src/test_data/certificates/pem_cert_from_pfx.pem
    '''
    from_ = kwargs['from']
    to_ = kwargs['to']

    in_ = kwargs['in']
    out = kwargs['out']
    inform = kwargs['inform']
    outform = kwargs['outform']

    func = get_openssl_func(from_, to_)
    result = func(in_=in_, out=out)
    print(result)
    
    x = run(result)
    print(x)
    # os.system(result)
    self.stdout.write(self.style.SUCCESS('Ok.'))


