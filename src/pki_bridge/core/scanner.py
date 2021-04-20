import json
import logging
import socket
from django.utils import timezone
from ssl import PROTOCOL_TLSv1
from threading import currentThread
from threading import Thread
from time import sleep
from time import time

from django.core.mail import send_mail
from django.core.paginator import Paginator
from OpenSSL import crypto
from OpenSSL import SSL
from pki_bridge.conf import db_settings
from pki_bridge.core.converter import (
    Converter,
)
from pki_bridge.core.utils import get_obj_admin_link
from pki_bridge.core.utils import run
from pki_bridge.models import Certificate
from pki_bridge.models import CertificateRequest
from pki_bridge.models import CertificateRequestScan
from pki_bridge.models import Host
from pki_bridge.models import HostScan


logger = logging.getLogger(__name__)


class CustomThread(Thread):
    """
    testable thread(raises errors while testing) which returns value after join()
    """

    def __init__(self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None
        self.exc = None

    def run(self):
        """Method representing the thread's activity.
        You may override this method in a subclass. The standard run() method
        invokes the callable object passed to the object's constructor as the
        target argument, if any, with sequential and keyword arguments taken
        from the args and kwargs arguments, respectively.
        """
        try:
            if self._target is not None:
                self._return = self._target(*self._args, **self._kwargs)
        except BaseException as e:
            self.exc = e
        finally:
            del self._target, self._args, self._kwargs

    def join(self, *args):
        """Wait until the thread terminates.
        This blocks the calling thread until the thread whose join() method is
        called terminates -- either normally or through an unhandled exception
        or until the optional timeout occurs.
        When the timeout argument is present and not None, it should be a
        floating point number specifying a timeout for the operation in seconds
        (or fractions thereof). As join() always returns None, you must call
        is_alive() after join() to decide whether a timeout happened -- if the
        thread is still alive, the join() call timed out.
        When the timeout argument is not present or None, the operation will
        block until the thread terminates.
        A thread can be join()ed many times.
        join() raises a RuntimeError if an attempt is made to join the current
        thread as that would cause a deadlock. It is also an error to join() a
        thread before it has been started and attempts to do so raises the same
        exception.
        """
        # super().join()
        Thread.join(self, *args)
        if self.exc:
            raise self.exc
        return self._return


class DbCertificatesScanner:
    def scan_db_certificates(self, verbosity=1):
        start = time()
        threads = []
        scan_results = []
        scans = CertificateRequestScan.objects.all()
        certificate_ids = scans.values_list("certificate_request__id", flat=True)
        certificates = CertificateRequest.objects.all()
        certificates = certificates.exclude(id__in=certificate_ids)
        per_page = db_settings.certificates_per_page
        if per_page:
            paginated_certificates = Paginator(certificates, per_page=per_page)
            page_numbers = paginated_certificates.page_range
        else:
            paginated_certificates = [
                certificates,
            ]
            page_numbers = [
                1,
            ]
        for page_number in page_numbers:
            if isinstance(paginated_certificates, list):
                certificates_page = paginated_certificates
            else:
                certificates_page = paginated_certificates.page(page_number)
            thread = CustomThread(target=self.scan_certificates_page, args=[certificates_page])
            thread.start()
            threads.append(thread)
        for thread in threads:
            scan_result = thread.join()
            scan_results.extend(scan_result)
        self.analyze_scan_results(scan_results)
        end = time() - start
        if verbosity > 1:
            print(f"{len(certificates)} hosts has been scanned in {end} seconds.")
        return scan_results

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
        certificate_request_scan = CertificateRequestScan.objects.create(
            certificate_request=certificate_request,
        )
        pem = certificate.pem
        try:
            pyopenssl_cert = Converter(pem, "pem", "pyopenssl_cert").cert
            Converter(pyopenssl_cert, "pyopenssl_cert", "json").cert
        except crypto.Error as e:
            msg = f"Couldnt convert pem to pyopenssl certificate because of error {type(e)}. Error message: {e}."
            certificate_request_scan.error_message = msg
            certificate_request_scan.save()
            return
        if db_settings.enable_mail_notifications:
            self.mail_requesters(certificate_request_scan)
        return {}

    def mail_requesters(self, certificate_request_scan):
        certificate_request = certificate_request_scan.certificate_request
        certificate = certificate_request.certificate
        link = get_obj_admin_link(certificate_request_scan)
        if certificate.is_expired:
            self.notify_about_expired(certificate_request_scan, certificate_request, certificate, link)
        if certificate.valid_days_to_expire < db_settings.days_to_expire:
            self.notify_about_almost_expired(certificate_request_scan, certificate_request, certificate, link)
        if certificate.is_self_signed:
            self.notify_about_self_signed(certificate_request_scan, certificate_request, certificate, link)
        if certificate.is_from_different_ca:
            self.notify_about_different_ca(certificate_request_scan, certificate_request, certificate, link)

    def notify_about_expired(self, certificate_request_scan, certificate_request, certificate, link):
        expiration_date = certificate.valid_till
        days = timezone.now() - expiration_date
        days = days.days
        recipient_list = [
            # "andrey.mendela@leonteq.com",
        ]
        if certificate_request.requester:
            recipient_list += [certificate_request.requester.email]
        send_mail(
            subject=f"Expired certificate notification #{certificate_request_scan.id}",
            message=f"Certificate of {certificate_request.id} has expired {expiration_date}({days} days ago). More info: {link}",
            from_email=db_settings.default_from_email,
            recipient_list=recipient_list,
            fail_silently=False,
        )

    def notify_about_almost_expired(self, certificate_request_scan, certificate_request, certificate, link):
        recipient_list = [
            # "andrey.mendela@leonteq.com",
        ]
        if certificate_request.requester:
            recipient_list += [certificate_request.requester.email]
        send_mail(
            subject=f"Expiration of {certificate_request.id} certificate.",
            message=f"Certificate of certificate_request #{certificate_request.id} will expire in {certificate.valid_days_to_expire} days. More info: {link}",
            from_email=db_settings.default_from_email,
            recipient_list=recipient_list,
            fail_silently=False,
        )

    def notify_about_self_signed(self, certificate_request_scan, certificate_request, certificate, link):
        recipient_list = [
            # "andrey.mendela@leonteq.com",
        ]
        if certificate_request.requester:
            recipient_list += [certificate_request.requester.email]
        send_mail(
            subject=f"Self-signed certificate on certificate_request #{certificate_request.id}.",
            message=f"Certificate of certificate_request #{certificate_request.id} is self-signed. Please change. More info: {link}",
            from_email=db_settings.default_from_email,
            recipient_list=recipient_list,
            fail_silently=False,
        )

    def notify_about_different_ca(self, certificate_request_scan, certificate_request, certificate, link):
        recipient_list = [
            # "andrey.mendela@leonteq.com",
        ]
        if certificate_request.requester:
            recipient_list += [certificate_request.requester.email]
        send_mail(
            subject=f"Foreign certificate on certificate_request #{certificate_request.id}.",
            message=f"Certificate of certificate_request #{certificate_request.id} is from different CA. Please change. More info: {link}",
            from_email=db_settings.default_from_email,
            recipient_list=recipient_list,
            fail_silently=False,
        )

    def analyze_scan_results(self, scan_results):
        # TODOv2: analyze_scan_results
        pass


class NetworkScanner:
    verbosity = 1

    def scan_hosts(self):
        start = time()
        scan_results = []
        threads = []
        hosts = Host.objects.filter(is_active=True)
        per_page = db_settings.hosts_per_page
        # hosts = hosts[:5000]
        per_page = 100
        if per_page:
            paginated_hosts = Paginator(hosts, per_page=per_page)
            page_numbers = paginated_hosts.page_range
        else:
            paginated_hosts = [
                hosts,
            ]
            page_numbers = [
                1,
            ]
        for page_number in page_numbers:
            if isinstance(paginated_hosts, list):
                hosts_page = paginated_hosts
            else:
                hosts_page = paginated_hosts.page(page_number)
            thread = CustomThread(target=self.scan_hosts_page, args=[hosts_page])
            thread.start()
            threads.append(thread)
        for thread in threads:
            scan_result = thread.join()
            scan_results.extend(scan_result)
        self.analyze_scan_results(scan_results)
        if self.verbosity > 1:
            end = time() - start
            print(f"{len(hosts)} hosts has been scanned in {end} seconds.")
        return scan_results

    def scan_hosts_page(self, hosts_page):
        scan_results = []
        for host in hosts_page:
            if not self.host_exists(host):
                continue
            ports = db_settings.ports
            for port in ports:
                scan_result = self.scan_host(host, port)
                scan_results.append(scan_result)
        return scan_results

    def scan_host(self, host, port):
        if self.verbosity > 1:
            print()
            print(f"INITIAL SCAN CREATION. {host.id}.{host.name}:{port}. {currentThread()}")
        scan = HostScan.objects.create(
            host=host,
            port=port,
        )
        host.last_scan = scan
        host.save()
        pyopenssl_cert = self.get_cert_of_host(host.name, port)
        if not isinstance(pyopenssl_cert, crypto.X509):
            msg = f"{host}:{port} didnt return certificate."
            msg += f"Error: {pyopenssl_cert}({type(pyopenssl_cert)})"
            scan.error_message = msg
            scan.save()
            return {
                "error_message": msg,
            }
        pem = self.get_pem_of_host(host.name, port)
        pyopenssl_pem = Converter(pyopenssl_cert, "pyopenssl_cert", "pem").cert
        if pyopenssl_pem != pem:
            msg = f"'openssl s_client -connect {host.name}:{port}' "
            msg += "and 'SSL.Connection.get_peer_certificate()' "
            msg += "returted different pem certificates."
            scan.error_message = msg
            scan.save()
            return {
                "error_message": msg,
            }
        pyopenssl_json_cert = Converter(pyopenssl_cert, "pyopenssl_cert", "json").cert
        # pyopenssl_json_cert = self.analyze_ssl(host.name, pyopenssl_json_cert)
        pyopenssl_cert2 = Converter(pem, "pem", "pyopenssl_cert").cert
        pyopenssl_json_cert2 = Converter(pyopenssl_cert2, "pyopenssl_cert", "json").cert
        if pyopenssl_json_cert2 != pyopenssl_json_cert:
            msg = "'Pem certificates of "
            msg += f"'openssl s_client -connect {host.name}:{port}' "
            msg += "and 'SSL.Connection.get_peer_certificate()' "
            msg += "returted different json values after convertations."
            scan.error_message = msg
            scan.save()
            return {
                "error_message": msg,
            }
        if self.verbosity > 1:
            print(f"{host}:{port}. {currentThread()}")
            print(pyopenssl_json_cert)
            print()
        certificate = Certificate.objects.create(
            pem=pem,
        )
        scan.certificate = certificate
        scan.save()
        if db_settings.enable_mail_notifications:
            result = self.mail_admins(host, port, certificate, scan)
            return result

    def mail_admins(self, host, port, certificate, scan):
        # TODOv2: analytics: save to db which mail was sent
        link = get_obj_admin_link(scan)
        if certificate.is_expired:
            self.mail_admins_about_expired(host, port, certificate, scan, link)
        if certificate.valid_days_to_expire < host.days_to_expire:
            self.mail_admins_about_almost_expired(host, port, certificate, scan, link)
        if certificate.is_self_signed:
            self.mail_admins_about_self_signed(host, port, certificate, scan, link)
        if certificate.is_from_different_ca:
            self.mail_admins_about_different_ca(host, port, certificate, scan, link)

    def mail_admins_about_expired(self, host, port, certificate, scan, link):
        expiration_date = certificate.valid_till
        days = timezone.now() - expiration_date
        days = days.days
        recipient_list = [
            # "andrey.mendela@leonteq.com",
        ]
        print(host.contacts)
        if host.contacts:
            recipient_list += [
                host.contacts,
            ]
        send_mail(
            subject=f"Expired certificate notification #{scan.id}.",
            message=f"Certificate of {host.name} has expired {expiration_date}({days} days ago). More info: {link}",
            from_email=db_settings.default_from_email,
            recipient_list=recipient_list,
            fail_silently=False,
        )

    def mail_admins_about_almost_expired(self, host, port, certificate, scan, link):
        recipient_list = [
            # "andrey.mendela@leonteq.com",
        ]
        if host.contacts:
            recipient_list += [
                host.contacts,
            ]
        send_mail(
            subject=f"Expiration of {host.name} certificate.",
            message=f"Certificate of host {host.name} will expire in {certificate.valid_days_to_expire} days. More info: {link}",
            from_email=db_settings.default_from_email,
            recipient_list=recipient_list,
            fail_silently=False,
        )

    def mail_admins_about_self_signed(self, host, port, certificate, scan, link):
        recipient_list = [
            # "andrey.mendela@leonteq.com",
        ]
        if host.contacts:
            recipient_list += [
                host.contacts,
            ]
        send_mail(
            subject=f"Self-signed certificate on {host.name}.",
            message=f"Certificate of host {host.name} is self-signed. Please change. More info: {link}",
            from_email=db_settings.default_from_email,
            recipient_list=recipient_list,
            fail_silently=False,
        )

    def mail_admins_about_different_ca(self, host, port, certificate, scan, link):
        recipient_list = [
            # "andrey.mendela@leonteq.com",
        ]
        if host.contacts:
            recipient_list += [
                host.contacts,
            ]
        send_mail(
            subject=f"Foreign certificate on host {host}.",
            message=f"Certificate of host {host} is from different CA. Please change. More info: {link}",
            from_email=db_settings.default_from_email,
            recipient_list=recipient_list,
            fail_silently=False,
        )

    def host_exists(self, host):
        try:
            socket.gethostbyname(host.name)
        except socket.gaierror as e:
            msg = f"Host {host} doesnt exist. Error: {e}"
            logger.warning(msg)
            return False
        return True

    def get_pem_of_host(self, host, port):
        # TODO v2: convert pyopenssl x509\cert\ssl object to pem string
        # https://stackoverflow.com/questions/9796694/pyopenssl-convert-certificate-object-to-pem-file
        args = [
            "openssl",
            "s_client",
            "-connect",
            f"{host}:{port}",
        ]
        begin = "-----BEGIN CERTIFICATE-----\n"
        end = "\n-----END CERTIFICATE-----"
        pem = run(args)
        # pem = pem.decode('utf-8')
        pem = pem.split(begin)
        pem = begin + pem[-1].strip()
        pem = pem.split(end)
        pem = pem[0].strip() + end
        pem = pem.strip()
        return pem

    def get_cert_of_host(self, host, port):
        host = self.filter_hostname(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SCAN_TIMEOUT = db_settings.scan_timeout
        sock.settimeout(SCAN_TIMEOUT)
        try:
            sock.connect((host, int(port)))
        except socket.timeout as e:
            return e
        except ConnectionRefusedError as e:
            return e
        sock.settimeout(None)
        osobj = SSL.Context(PROTOCOL_TLSv1)
        oscon = SSL.Connection(osobj, sock)
        oscon.set_tlsext_host_name(host.encode())
        oscon.set_connect_state()
        try:
            oscon.do_handshake()
        except SSL.SysCallError as e:
            return e
        except SSL.Error as e:
            return e
        cert = oscon.get_peer_certificate()
        sock.close()
        return cert

    def filter_hostname(self, host):
        host = host.replace("http://", "").replace("https://", "").replace("/", "")
        return host

    def analyze_ssl(self, host, context):
        try:
            from urllib.request import urlopen
        except ImportError:
            from urllib2 import urlopen
        api_url = "https://api.ssllabs.com/api/v3/"
        while True:
            main_request = json.loads(urlopen(api_url + f"analyze?host={host}").read().decode("utf-8"))
            if main_request["status"] in ("DNS", "IN_PROGRESS"):
                sleep(5)
                continue
            elif main_request["status"] == "READY":
                break
        endpoint_data = json.loads(urlopen(api_url + "getEndpointData?host={}&s={}".format(host, main_request["endpoints"][0]["ipAddress"])).read().decode("utf-8"))
        if endpoint_data["statusMessage"] == "Certificate not valid for domain name":
            return context
        context[host]["grade"] = main_request["endpoints"][0]["grade"]
        context[host]["poodle_vuln"] = endpoint_data["details"]["poodle"]
        context[host]["heartbleed_vuln"] = endpoint_data["details"]["heartbleed"]
        context[host]["heartbeat_vuln"] = endpoint_data["details"]["heartbeat"]
        context[host]["freak_vuln"] = endpoint_data["details"]["freak"]
        context[host]["logjam_vuln"] = endpoint_data["details"]["logjam"]
        context[host]["drownVulnerable"] = endpoint_data["details"]["drownVulnerable"]
        return context

    def analyze_scan_results(self, scan_results):
        # TODOv2: analyze_scan_results
        pass


class Scanner(NetworkScanner, DbCertificatesScanner):
    """
    Scanner().scan_network()
    Scanner().get_cert_of_host()
    Scanner().get_pem_of_host()
    """

    # https://www.google.com/search?q=openssl+get+certificate+info+from+website
    # https://www.sslshopper.com/article-most-common-openssl-commands.html
    # https://stackoverflow.com/questions/7885785/using-openssl-to-get-the-certificate-from-a-server
    # https://gist.github.com/gdamjan/55a8b9eec6cf7b771f92021d93b87b2c

    def scan_network(self):
        self.scan_hosts()
        self.scan_db_certificates()
