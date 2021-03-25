import threading
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from django.contrib.sites.models import Site
from django.core.paginator import Paginator

from threading import Thread
import socket
import os
from datetime import timedelta, datetime
from ssl import PROTOCOL_TLSv1
from time import sleep, time
from OpenSSL import SSL, crypto
import json
import logging

from pki_bridge.conf import db_settings
from pki_bridge.core.utils import (
    run,
)
from pki_bridge.models import (
    # Network,
    Scan,
    Host,
)


logger = logging.getLogger(__name__)

# SCAN_TIMEOUT = 120
SCAN_TIMEOUT = 2


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


def set_openssl_version():
    openssl_version = get_openssl_version()
    msg = f'Version of openssl is: "{openssl_version}"'
    logger.info(msg)


def decode_pem_into_cert(pem):
    cert = crypto.load_certificate(
        crypto.FILETYPE_PEM,
        pem,
    )
    cert = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert)
    cert = cert.decode('utf-8')
    return cert


def get_pem(host, port):
    args = [
        "openssl",
        "s_client",
        "-connect",
        f'{host}:{port}',
    ]
    begin = '-----BEGIN CERTIFICATE-----\n'
    end = '\n-----END CERTIFICATE-----'
    pem = run(args)
    # pem = pem.decode('utf-8')
    pem = pem.split(begin)
    pem = begin + pem[-1].strip()
    pem = pem.split(end)
    pem = pem[0].strip() + end
    return pem


# https://www.google.com/search?q=openssl+get+certificate+info+from+website
# https://www.sslshopper.com/article-most-common-openssl-commands.html
# https://stackoverflow.com/questions/7885785/using-openssl-to-get-the-certificate-from-a-server
# https://gist.github.com/gdamjan/55a8b9eec6cf7b771f92021d93b87b2c


def scan_network():
    start = time()

    threads = []
    hosts = Host.objects.filter(is_active=True)
    hosts = hosts[10:40]

    per_page = 8
    paginated_hosts = Paginator(hosts, per_page=per_page)
    page_numbers = paginated_hosts.page_range
    for page_number in page_numbers:
        hosts_page = paginated_hosts.page(page_number)
        thread = Thread(target=scan_page, args=[hosts_page])
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    end = time() - start
    print(end)
    print(f'{len(hosts)} hosts has been scanned in {end} seconds.')


def scan_page(hosts_page):
    for host in hosts_page:
        scan_host(host)


def scan_host(host):
    ports = [
        443,
        8081,
        8443,
        8083,
    ]
    try:
        socket.gethostbyname(host.host)
    except socket.gaierror as e:
        msg = f'Host {host} doesnt exist. Error: {e}'
        print(msg)
        logger.warning(msg)
        return
    for port in ports:
        result = SSLChecker().show_result(host.host, port)
        # print()
        if result != {}:
            print(f"{host}:{port} result: {result}. {threading.currentThread()}")
        # print()
        # pem = get_pem(host.host, port)
        # cert = decode_pem_into_cert(pem)
        # print()
        # print(cert)
        # print(host)
        # print()
        # scan = create_scan(host, result, pem, cert)
        # mail_admins(host, result, scan)




def create_scan(host, result, pem, cert):
    scan = Scan.objects.create(
        host=host,
        result=json.dumps(result, indent=4),
        pem=pem,
        cert=cert,
        hostname=result['host'],
        issued_to=result['issued_to'],
        issued_o=result['issued_o'],
        issuer_c=result['issuer_c'],
        issuer_o=result['issuer_o'],
        issuer_ou=result['issuer_ou'],
        issuer_cn=result['issuer_cn'],
        cert_sn=result['cert_sn'],
        cert_sha1=result['cert_sha1'],
        cert_alg=result['cert_alg'],
        cert_ver=result['cert_ver'],
        cert_sans=result['cert_sans'],
        cert_exp=result['cert_exp'],
        valid_from=result['valid_from'],
        valid_till=result['valid_till'],
        validity_days=result['validity_days'],
        days_left=result['days_left'],
        valid_days_to_expire=result['valid_days_to_expire'],
        tcp_port=result['tcp_port'],
    )
    host.last_scan = scan
    host.save()
    return scan


def mail_admins(host, result, scan):

    domain = Site.objects.get_current().domain
    link = reverse(f'admin:{scan._meta.app_label}_{scan._meta.model_name}_change', args=[scan.id, ])
    link = f'https://{domain}{link}'

    valid_days_to_expire = result['valid_days_to_expire']
    is_expired = result['cert_exp']

    # TODO: host.days_to_expire
    # days_to_expire = host.days_to_expire
    days_to_expire = 3000
    # TODO: check if is not selfsigned
    # https://stackoverflow.com/questions/56763385/determine-if-ssl-certificate-is-self-signed-using-python
    is_self_signed = False
    # TODO: check if is not from different CA(issuer_cn field)
    is_from_different_ca = False

    perform_send = False
    if is_expired:
        perform_send = True
        # TODO: count days or replace with date
        days = 'a few'
        subject = f"Certificate of {host} has expired {days} days ago. More info: {link}"
        message = f''
        recipient_list = []
        recipient_list += [
            'andrey.mendela@leonteq.com',
        ]
        if host.contacts:
            recipient_list += [
                host.contacts,
            ]
    elif valid_days_to_expire < days_to_expire:
        perform_send = True
        subject = f"Expiration of {host} certificate."
        message = f"Certificate of host {host} will expire in {valid_days_to_expire} days. More info: {link}"
        recipient_list = []
        recipient_list += [
            'andrey.mendela@leonteq.com',
        ]
        if host.contacts:
            recipient_list += [
                host.contacts,
            ]
    elif is_self_signed:
        perform_send = True
        subject = f"Self-signed certificate on {host}."
        message = f"Certificate of host {host} is self-signed. Please change. More info: {link}"
        recipient_list = []
        recipient_list += [
            'andrey.mendela@leonteq.com',
        ]
        if host.contacts:
            recipient_list += [
                host.contacts,
            ]
    elif is_from_different_ca:
        perform_send = True
        subject = f"Foreign certificate on host {host}."
        message = f"Certificate of host {host} is from different CA. Please change. More info: {link}"
        recipient_list = []
        recipient_list += [
            'andrey.mendela@leonteq.com',
        ]
        if host.contacts:
            recipient_list += [
                host.contacts,
            ]
    print(perform_send)
    print(recipient_list)
    if False:
    # if perform_send:
        print(message)
        send_mail(
            subject=subject,
            message=message,
            from_email=db_settings.default_from_email,
            recipient_list=recipient_list,
            fail_silently=False,
        )


class SSLChecker:

    def show_result(self, host, port, analyze=False):
        context = {}
        host = self.filter_hostname(host)
        cert = self.get_cert(host, port)
        if isinstance(cert, crypto.X509):
            context = self.get_cert_info(host, cert)
            context['tcp_port'] = int(port)
            if analyze:
                context = self.analyze_ssl(host, context)
        return context

    def get_cert(self, host, port, socks=None):
        if socks:
            import socks
            socks_host = self.filter_hostname(socks)
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, socks_host, int(port), True)
            socket.socket = socks.socksocket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SCAN_TIMEOUT)
        try:
            sock.connect((host, int(port)))
        except socket.timeout as e:
            # print(f'{host}, {port}, {e}')
            return e
            # return
        except ConnectionRefusedError as e:
            # print(f'{host}, {port}, {e}')
            return e
            # return
        sock.settimeout(None)
        osobj = SSL.Context(PROTOCOL_TLSv1)
        oscon = SSL.Connection(osobj, sock)
        oscon.set_tlsext_host_name(host.encode())
        oscon.set_connect_state()
        try:
            oscon.do_handshake()
        except SSL.SysCallError as e:
            # print(f'{host}, {port}, {e}')
            return e
            # return
        except SSL.Error as e:
            # print(f'{host}, {port}, {e}')
            return e
            # return
        cert = oscon.get_peer_certificate()
        sock.close()
        # print(f'{host}, {port}, {cert}')
        return cert

    def analyze_ssl(self, host, context):
        try:
            from urllib.request import urlopen
        except ImportError:
            from urllib2 import urlopen
        api_url = 'https://api.ssllabs.com/api/v3/'
        while True:
            main_request = json.loads(urlopen(api_url + 'analyze?host={}'.format(host)).read().decode('utf-8'))
            if main_request['status'] in ('DNS', 'IN_PROGRESS'):
                sleep(5)
                continue
            elif main_request['status'] == 'READY':
                break
        endpoint_data = json.loads(urlopen(api_url + 'getEndpointData?host={}&s={}'.format(
            host, main_request['endpoints'][0]['ipAddress'])).read().decode('utf-8'))
        if endpoint_data['statusMessage'] == 'Certificate not valid for domain name':
            return context
        context[host]['grade'] = main_request['endpoints'][0]['grade']
        context[host]['poodle_vuln'] = endpoint_data['details']['poodle']
        context[host]['heartbleed_vuln'] = endpoint_data['details']['heartbleed']
        context[host]['heartbeat_vuln'] = endpoint_data['details']['heartbeat']
        context[host]['freak_vuln'] = endpoint_data['details']['freak']
        context[host]['logjam_vuln'] = endpoint_data['details']['logjam']
        context[host]['drownVulnerable'] = endpoint_data['details']['drownVulnerable']
        return context

    def get_cert_sans(self, x509cert):
        san = ''
        ext_count = x509cert.get_extension_count()
        for i in range(0, ext_count):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
        san = san.replace(',', ';')
        return san

    def get_cert_info(self, host, cert):
        context = {}
        cert_subject = cert.get_subject()
        context['host'] = host
        context['issued_to'] = cert_subject.CN
        context['issued_o'] = cert_subject.O
        context['issuer_c'] = cert.get_issuer().countryName
        context['issuer_o'] = cert.get_issuer().organizationName
        context['issuer_ou'] = cert.get_issuer().organizationalUnitName
        context['issuer_cn'] = cert.get_issuer().commonName
        context['cert_sn'] = str(cert.get_serial_number())
        context['cert_sha1'] = cert.digest('sha1').decode()
        context['cert_alg'] = cert.get_signature_algorithm().decode()
        context['cert_ver'] = cert.get_version()
        context['cert_sans'] = self.get_cert_sans(cert)
        context['cert_exp'] = cert.has_expired()
        # context['cert_valid'] = False if cert.has_expired() else True
        valid_from = datetime.strptime(cert.get_notBefore().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_from'] = valid_from.strftime('%Y-%m-%d')
        valid_till = datetime.strptime(cert.get_notAfter().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_till'] = valid_till.strftime('%Y-%m-%d')
        context['validity_days'] = (valid_till - valid_from).days
        now = datetime.now()
        context['days_left'] = (valid_till - now).days
        context['valid_days_to_expire'] = (datetime.strptime(context['valid_till'],
                                           '%Y-%m-%d') - datetime.now()).days
        return context

    def filter_hostname(self, host):
        host = host.replace('http://', '').replace('https://', '').replace('/', '')
        return host
