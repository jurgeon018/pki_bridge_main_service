from django.conf import settings
from django.core.mail import send_mail
from django.core.paginator import Paginator

from threading import Thread, currentThread
from ssl import PROTOCOL_TLSv1
from time import sleep, time
from OpenSSL import SSL, crypto
import json
import logging
import socket

from pki_bridge.conf import db_settings
from pki_bridge.core.utils import (
    run,
    get_obj_admin_link,
)
from pki_bridge.core.converter import (
    Converter,
)
from pki_bridge.models import (
    # Network,
    CertificateRequest,
    CertificateRequestScan,
    Certificate,
    HostScan,
    Host,
)


logger = logging.getLogger(__name__)


class ThreadWithReturnValue(Thread):

    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs={}, Verbose=None):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None

    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)

    def join(self, *args):
        Thread.join(self, *args)
        return self._return


class DbCertificatesScanner:

    def scan_db_certificates(self):
        start = time()

        threads = []
        certificates = CertificateRequest.objects.all()
        # certificates = certificates.filter()
        # certificates = certificates[10:40]

        per_page = db_settings.certificates_per_page
        if per_page:
            paginated_certificates = Paginator(certificates, per_page=per_page)
            page_numbers = paginated_certificates.page_range
        else:
            paginated_certificates = [certificates, ]
            page_numbers = [1, ]
        for page_number in page_numbers:
            certificates_page = paginated_certificates.page(page_number)
            thread = ThreadWithReturnValue(target=self.scan_certificates_page, args=[certificates_page])
            # thread = Thread(target=self.scan_certificates_page, args=[certificates_page])
            thread.start()
            threads.append(thread)
        scan_results = []
        for thread in threads:
            scan_result = thread.join()
            scan_results.extend(scan_result)
        self.analyze_scan_results(scan_results)
        end = time() - start
        # print(end)
        print(f'{len(certificates)} hosts has been scanned in {end} seconds.')

    def analyze_scan_results(self, scan_results):
        # TODOv2: analyze_scan_results
        pass

    def scan_certificates_page(self, certificates_page):
        scan_results = []
        for certificate_request in certificates_page:
            scan_result = self.scan_db_certficate(certificate_request)
            scan_results.append(scan_result)
        return scan_results

    def scan_db_certficate(self, certificate_request):
        certificate = certificate_request.certificate
        if not certificate:
            return
        # print()
        # print("certificate_request: ", certificate_request)
        # print("certificate: ", certificate)
        certificate_request_scan = CertificateRequestScan.objects.create(
            certificate_request=certificate_request,
        )
        pem = certificate.pem
        # pem = 'sdf'
        # pem = pem[:40] + pem[50:]
        try:
            pyopenssl_cert = Converter(pem, 'pem', 'pyopenssl_cert').cert
            Converter(pyopenssl_cert, 'pyopenssl_cert', 'json').cert
        except crypto.Error as e:
            msg = f'Couldnt convert pem to pyopenssl certificate because of error {type(e)}. Error message: {e}.'
            # print(msg)
            certificate_request_scan.error_message = msg
            certificate_request_scan.save()
            return
        self.mail_requesters(certificate_request, certificate_request_scan)

    def mail_requesters(self, certificate_request, certificate_request_scan):
        certificate = certificate_request.certificate
        valid_days_to_expire = certificate.valid_days_to_expire
        is_expired = certificate.is_expired
        days_to_expire = db_settings.days_to_expire
        # days_to_expire = 3000
        is_self_signed = certificate.is_self_signed
        is_from_different_ca = certificate.is_from_different_ca
        # print('certificate: ', certificate)
        # print("valid_days_to_expire: ", valid_days_to_expire)
        # print("days_to_expire: ", days_to_expire)
        # print("is_expired: ", is_expired)
        # print("is_self_signed: ", is_self_signed)
        # print("is_from_different_ca: ", is_from_different_ca, certificate.issuer_cn)
        # return
        link = get_obj_admin_link(certificate_request_scan)
        if is_expired:
            # TODO: count days or replace with date
            # TODO: add real emails
            days = 'a few'
            subject = f"Certificate of {certificate_request.id} has expired {days} days ago. More info: {link}"
            message = f"Certificate of {certificate_request.id} has expired {days} days ago. More info: {link}"
            recipient_list = []
            recipient_list += [
                'andrey.mendela@leonteq.com',
            ]
            if certificate_request.requester:
                recipient_list += [
                    certificate_request.requester.email
                ]
            if db_settings.enable_mail_notifications:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=db_settings.default_from_email,
                    recipient_list=recipient_list,
                    fail_silently=False,
                )
        if valid_days_to_expire < days_to_expire:
            subject = f"Expiration of {certificate_request.id} certificate."
            message = f"Certificate of certificate_request #{certificate_request.id} "
            message += f"will expire in {valid_days_to_expire} days. More info: {link}"
            recipient_list = []
            recipient_list += [
                'andrey.mendela@leonteq.com',
            ]
            if certificate_request.requester:
                recipient_list += [
                    certificate_request.requester.email
                ]
            if db_settings.enable_mail_notifications:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=db_settings.default_from_email,
                    recipient_list=recipient_list,
                    fail_silently=False,
                )
        if is_self_signed:
            subject = f"Self-signed certificate on certificate_request #{certificate_request.id}."
            message = f"Certificate of certificate_request #{certificate_request.id} is self-signed. Please change. More info: {link}"
            recipient_list = []
            recipient_list += [
                'andrey.mendela@leonteq.com',
            ]
            if certificate_request.requester:
                recipient_list += [
                    certificate_request.requester.email
                ]
            if db_settings.enable_mail_notifications:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=db_settings.default_from_email,
                    recipient_list=recipient_list,
                    fail_silently=False,
                )
        if is_from_different_ca:
            subject = f"Foreign certificate on certificate_request #{certificate_request.id}."
            message = f"Certificate of certificate_request #{certificate_request.id} is from different CA. Please change. More info: {link}"
            recipient_list = []
            recipient_list += [
                'andrey.mendela@leonteq.com',
            ]
            if certificate_request.requester:
                recipient_list += [
                    certificate_request.requester.email
                ]
            if db_settings.enable_mail_notifications:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=db_settings.default_from_email,
                    recipient_list=recipient_list,
                    fail_silently=False,
                )


class NetworkScanner:

    def scan_hosts(self):
        start = time()

        threads = []
        hosts = Host.objects.filter(is_active=True)
        per_page = db_settings.hosts_per_page
        if per_page:
            paginated_hosts = Paginator(hosts, per_page=per_page)
            page_numbers = paginated_hosts.page_range
        else:
            paginated_hosts = [hosts, ]
            page_numbers = [1, ]
        for page_number in page_numbers:
            hosts_page = paginated_hosts.page(page_number)
            # thread = Thread(target=self.scan_hosts_page, args=[hosts_page])
            thread = ThreadWithReturnValue(target=self.scan_hosts_page, args=[hosts_page])
            thread.start()
            threads.append(thread)
        scan_results = []
        for thread in threads:
            scan_result = thread.join()
            scan_results.extend(scan_result)
        self.analyze_scan_results(scan_results)
        end = time() - start
        # print(end)
        print(f'{len(hosts)} hosts has been scanned in {end} seconds.')

    def analyze_scan_results(self, scan_results):
        # TODOv2: analyze_scan_results
        pass

    def scan_hosts_page(self, hosts_page):
        for host in hosts_page:
            if not self.host_exists(host):
                print(f'host {host} doesnt exist')
                return
            ports = db.ports
            scan_results = []
            for port in ports:
                scan_result = self.scan_host(host, port)
                scan_results.append(scan_result)
            return scan_results

    def scan_host(self, host, port):
        # print()
        # print(f"{host}:{port}. {currentThread()}")
        scan = HostScan.objects.create(
            host=host,
            port=port,
        )
        host.last_scan = scan
        host.save()
        pyopenssl_cert = self.get_cert_of_host(host.name, port)
        if not isinstance(pyopenssl_cert, crypto.X509):
            msg = f'{host}:{port} didnt return certificate.'
            msg += f'Error: {pyopenssl_cert}({type(pyopenssl_cert)})'
            raise(msg)
            scan.error_message = msg
            scan.save()
            return {

            }
        pem = self.get_pem_of_host(host.name, port)
        pyopenssl_pem = Converter(pyopenssl_cert, 'pyopenssl_cert', 'pem').cert
        if pyopenssl_pem != pem:
            msg = f"'openssl s_client -connect {host}:{port}' "
            msg += "and 'SSL.Connection.get_peer_certificate()' "
            msg += "returted different pem certificates."
            scan.error_message = msg
            scan.save()
            return {

            }
        pyopenssl_json_cert = Converter(pyopenssl_cert, 'pyopenssl_cert', 'json').cert
        # pyopenssl_json_cert = self.analyze_ssl(host.name, pyopenssl_json_cert) 
        pyopenssl_cert2 = Converter(pem, 'pem', 'pyopenssl_cert').cert
        pyopenssl_json_cert2 = Converter(pyopenssl_cert2, 'pyopenssl_cert', 'json').cert
        if pyopenssl_json_cert2 != pyopenssl_json_cert:
            msg = "'Pem certificates of "
            msg += f"'openssl s_client -connect {host}:{port}' "
            msg += "and 'SSL.Connection.get_peer_certificate()' "
            msg += "returted different json values after convertations."
            scan.error_message = msg
            scan.save()
            return {
                'error_message': msg,
            }
        certificate = Certificate.objects.create(
            pem=pem,
        )
        # print('certificate:', certificate)
        scan.certificate = certificate
        scan.save()
        result = self.mail_admins(host, port, certificate, scan)
        return result

    def mail_admins(self, host, port, certificate, scan):
        valid_days_to_expire = certificate.valid_days_to_expire
        is_expired = certificate.is_expired
        days_to_expire = host.days_to_expire
        # days_to_expire = 3000
        is_self_signed = certificate.is_self_signed
        is_from_different_ca = certificate.is_from_different_ca
        # print('certificate: ', certificate)
        # print("valid_days_to_expire: ", valid_days_to_expire)
        # print("days_to_expire: ", days_to_expire)
        # print("is_expired: ", is_expired)
        # print("is_self_signed: ", is_self_signed)
        # print("is_from_different_ca: ", is_from_different_ca)
        # return
        # TODO: add real emails
        # TODOv2: analytics: save to db which mail was sent
        link = get_obj_admin_link(scan)
        if is_expired:
            # TODO: count days or replace with date
            days = 'a few'
            subject = f"Certificate of {host} has expired {days} days ago. More info: {link}"
            message = ''
            recipient_list = []
            recipient_list += [
                'andrey.mendela@leonteq.com',
            ]
            if host.contacts:
                recipient_list += [
                    host.contacts,
                ]
            if db_settings.enable_mail_notifications:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=db_settings.default_from_email,
                    recipient_list=recipient_list,
                    fail_silently=False,
                )
        if valid_days_to_expire < days_to_expire:
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
            if db_settings.enable_mail_notifications:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=db_settings.default_from_email,
                    recipient_list=recipient_list,
                    fail_silently=False,
                )
        if is_self_signed:
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
            if db_settings.enable_mail_notifications:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=db_settings.default_from_email,
                    recipient_list=recipient_list,
                    fail_silently=False,
                )
        if is_from_different_ca:
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
            if db_settings.enable_mail_notifications:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=db_settings.default_from_email,
                    recipient_list=recipient_list,
                    fail_silently=False,
                )

    def host_exists(self, host):
        try:
            socket.gethostbyname(host.name)
        except socket.gaierror as e:
            msg = f'Host {host} doesnt exist. Error: {e}'
            print(msg)
            logger.warning(msg)
            return False
        return True

    def get_pem_of_host(self, host, port):
        # TODO: convert pyopenssl x509\cert\ssl object to pem string
        # https://stackoverflow.com/questions/9796694/pyopenssl-convert-certificate-object-to-pem-file
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
        pem = pem.strip()
        return pem

    def get_cert_of_host(self, host, port, socks=None):
        host = self.filter_hostname(host)
        # if socks:
        #     from pki_bridge.core import socks
        #     socks_host = self.filter_hostname(socks)
        #     socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, socks_host, int(port), True)
        #     socket.socket = socks.socksocket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # SCAN_TIMEOUT = 120
        # SCAN_TIMEOUT = 2
        SCAN_TIMEOUT = db_settings.scan_timeout
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
            return e
            # return
        except SSL.Error as e:
            return e
            # return
        cert = oscon.get_peer_certificate()
        sock.close()
        return cert

    def filter_hostname(self, host):
        host = host.replace('http://', '').replace('https://', '').replace('/', '')
        return host

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


class Scanner(NetworkScanner, DbCertificatesScanner):
    '''
    Scanner().scan_network()
    Scanner().get_cert_of_host()
    Scanner().get_pem_of_host()
    '''
    # https://www.google.com/search?q=openssl+get+certificate+info+from+website
    # https://www.sslshopper.com/article-most-common-openssl-commands.html
    # https://stackoverflow.com/questions/7885785/using-openssl-to-get-the-certificate-from-a-server
    # https://gist.github.com/gdamjan/55a8b9eec6cf7b771f92021d93b87b2c

    def scan_network(self):
        self.scan_hosts()
        self.scan_db_certificates()
