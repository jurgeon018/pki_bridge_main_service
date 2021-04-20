import logging
import socket
from datetime import timedelta

import OpenSSL
import requests
import urllib3
from django.conf import settings
from django.core.mail import send_mail
from django.http import (
    HttpResponse,
    # FileResponse,
)
from django.utils import timezone
from pki_bridge.conf import db_settings
from pki_bridge.core.converter import Converter
from pki_bridge.core.ldap import (
    entry_is_in_ldap,
)
from pki_bridge.core.scanner import Scanner
from pki_bridge.core.utils import get_obj_admin_link
from pki_bridge.management import (
    update_templates,
)
from pki_bridge.models import Certificate
from pki_bridge.models import CertificateRequest
from pki_bridge.models import Command
from pki_bridge.models import Host
from pki_bridge.models import Note
from pki_bridge.models import ProjectUser
from pki_bridge.models import Requester
from pki_bridge.models import Template
from pki_bridge.tasks import celery_scan_db_certificates
from pki_bridge.tasks import celery_scan_hosts
from pki_bridge.tasks import celery_scan_network
from rest_framework.decorators import api_view

# from tempfile import gettempdir

# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BASE_DIR = settings.BASE_DIR
WINDOWS_SECRET_KEY = settings.WINDOWS_SECRET_KEY
WINDOWS_URL = settings.WINDOWS_URL

logger = logging.getLogger(__name__)


def throttle_request(requester):
    allowed_requests = db_settings.allowed_requests
    reset_period = db_settings.reset_period
    if allowed_requests and reset_period:
        dt = timezone.now() - timedelta(hours=reset_period)
        certificate_requests = CertificateRequest.objects.filter(
            requester__email=requester,
            created__gte=dt,
        ).order_by("created")
        if certificate_requests.count() > db_settings.allowed_requests:
            last_request = certificate_requests.last()
            again = last_request.created + timedelta(hours=reset_period) - timezone.now()
            again = divmod(again.total_seconds(), 60)
            minutes = round(again[0])
            seconds = round(again[-1])
            response = ""
            response += f"You've reached the limit of request({allowed_requests} per {reset_period} hours).\n"
            response += f"Try again in {minutes} minutes and {seconds} seconds.\n"
            return response


def validate_SAN(SAN):
    if SAN:
        SAN = SAN.replace(" ", "")
    return SAN


def validate_template_rights(requester_email, password, template):
    if db_settings.enable_template_rights_validation is False:
        return None
    user = ProjectUser.objects.filter(email=requester_email).first()
    if user is not None:
        templates = user.templates.all().values_list("name", flat=True)
        if not user.check_password(password):
            error = "Password is incorrect\n"
        elif template not in templates:
            error = "You do not have rights to use this template.\n"
        else:
            error = None
        return error
    else:
        error = "User does not exist.\n"
        return error


def create_certificate_request(pem, requester_email, template, domain, SAN, csr, query):
    note = query.get("note")
    enable_sending_certificate_to_mail = query.get("enable_sending_certificate_to_mail", "true")
    requester, _ = Requester.objects.get_or_create(
        email=requester_email,
    )
    certificate = Certificate.objects.create(
        pem=pem,
    )
    certificate_request = CertificateRequest.objects.create(
        requester=requester,
        template=template,
        domain=domain,
        SAN=SAN,
        csr=csr,
        certificate=certificate,
        # TODO v2: save "env" to db ??
        # env=env,
        # TODO v2: save "certformat" to db ??
        # certformat=certformat,
    )
    if note:
        Note.objects.create(
            certificate_request=certificate_request,
            text=note,
        )
    if enable_sending_certificate_to_mail == "true":
        send_certificate_to_mail(requester_email, certificate_request)
    return certificate_request


def get_intermediary_response(csr, domain, template, SAN):
    try:
        data = {
            # "secret_key": WINDOWS_SECRET_KEY,
            # "csr": csr,
            # "domain": domain,
            # "template": template,
            # "san": SAN,

            'csr': csr,
            'common_name':common_name,
        }
        headers = {
            'Authorization': 'token'
        }
        response = requests.post(
            url='vaultproject.io/pki/sign-certificate/',
            # url=f"{WINDOWS_URL}/submit",
            verify=False,
            json=data,
            # files={
            #     'data': (None, json.dumps(data), 'application/json'),
            #     'csr': ('csr_file', csr_file, 'application/octet-stream')
            # }
            headers=headers,
        )

        response = response.json()
    except requests.exceptions.ConnectionError as e:
        if settings.DEBUG and settings.MOCK_INTERMEDIARY_RESPONSE:
            test_cert_filepath = BASE_DIR / "fixtures" / "test_certificate.pem"
            with open(test_cert_filepath, encoding="utf-8") as cert_file:
                response = {"certificate": cert_file.read()}
        else:
            response = f"Cannot connect to intermediary.\n{e}.\n"
    except Exception as e:
        response = f"Error occured. {e}. \n"
    return response


def build_mail_message(certificate_request):
    message = ""
    message += f"Certificate request id: {certificate_request.id}\n"
    message += f"Certificate id: {certificate_request.certificate.id}\n"
    message += f"Certificate request link: {get_obj_admin_link(certificate_request)}\n"
    message += f"Certificate link: {get_obj_admin_link(certificate_request.certificate)}\n"
    message += f"Certificate pem: \n{certificate_request.certificate.pem}\n"
    message += f"CSR: \n{certificate_request.csr}\n"
    return message


def send_certificate_to_mail(requester_email, certificate_request):
    try:
        send_mail(
            subject=f"Certificate request #{certificate_request.id}",
            message=build_mail_message(certificate_request),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[
                requester_email,
                # 'andrey.mendela@leonteq.com'
            ],
            fail_silently=False,
        )
    except socket.gaierror as e:
        msg = f"Couldnt send main because of error: {e}"
        logger.error(msg)


@api_view(["POST"])
def signcert(request):
    default_domain = r"CHVIRPKIPRD103.fpprod.corp\Leonteq Class 3 Issuing CA"
    default_template = "LeonteqWebSrvManualEnroll"

    query = request.data
    files = request.FILES

    requester_email = query["requester"]
    password = query.get("password")
    response_format = query.get("response_format", "text")
    template = query.get("template", default_template)
    domain = query.get("domain", default_domain)
    SAN = query.get("SAN")
    # env = query.get('env')
    # certformat = query.get('certformat', 'pem')
    SAN = validate_SAN(SAN)

    # certformat_invalid_msg = validate_certformat(certformat)
    # if certformat_invalid_msg is not None:
    #     return HttpResponse(certformat_invalid_msg, status=400)

    throttling_result = throttle_request(requester_email)
    if throttling_result is not None:
        return HttpResponse(throttling_result, status=403)

    template_rigths_error = validate_template_rights(requester_email, password, template)
    if template_rigths_error is not None:
        return HttpResponse(template_rigths_error, status=400)

    templates = Template.objects.all().values_list("name", flat=True)
    if template not in templates and not db_settings.allow_any_template:
        response = "Invalid template specified. List of templates you can get from here: /api/v1/listtemplates/\n"
        return HttpResponse(response, status=400)

    if not entry_is_in_ldap(requester_email):
        response = f'Email "{requester_email}" is not in ldap.\n'
        return HttpResponse(response, status=403)

    csr_file = files.get("csr")
    csr = csr_file.read().decode()
    intermediary_response = get_intermediary_response(csr, domain, template, SAN)
    try:
        pem = intermediary_response["certificate"]
    except KeyError:
        return HttpResponse(intermediary_response, status=500)
    try:
        certificate_request = create_certificate_request(
            pem,
            requester_email,
            template,
            domain,
            SAN,
            csr,
            query,
        )
    except OpenSSL.crypto.Error as e:
        response = f"Error: {e}"
        return HttpResponse(response, status=500)
    if response_format == "text":
        response = ""
        response += f"{pem}\n\n\n"
        response += "Certificate request has been signed successfully. "
        response += f"Its id is {certificate_request.id}.\n"
        response += "Certificate has been sent to your email in pem format.\n"
        return HttpResponse(response, status=200)
    elif response_format == "file":
        # TODO v2: return response as file
        # return signcert_file_response(pem)
        return HttpResponse(f"Response format {response_format} is not implemented.\n", status=400)
    else:
        return HttpResponse(f"Response format {response_format} is not implemented.\n", status=400)


# def validate_certformat(certformat):
#     certformats = [k for k, _ in Converter().get_formats_mapper().items()]
#     if certformat not in certformats:
#         # formats = 'pem, der, p7b, p12'
#         formats = ', '.join(certformats)
#         response = f"\nInvalid format. Certformat must be one of: {formats}\n"
#         return response


# def signcert_file_response(pem):
#     import os
#     path = os.path.join(gettempdir(), 'file.cer')
#     with open(path, 'w') as f:
#         f.write(pem)
#     return  (open
# )(path, 'rb'))


@api_view(["POST", "GET"])
def listtemplates(request):
    if db_settings.update_templates_from_ca:
        update_templates()
    tempates = Template.objects.all()
    templates_string = ""
    for template in tempates:
        templates_string += f"{template.name}: {template.description}\n"
    return HttpResponse(templates_string)


@api_view(["POST", "GET"])
def pingca(request):
    # TODO v2: ping vault
    # url = f'{WINDOWS_URL}/pingca'
    # response = requests.get(url)
    response = "Not implemented"
    return HttpResponse(response)


@api_view(["POST", "GET"])
def run_scanner_view(request, id=None):
    # TODO v2: block next request to run_scanner_view untill scan session has finished
    if request.method == "POST":
        query = request.data
    elif request.method == "GET":
        query = request.query_params
    SCANNER_SECRET_KEY = db_settings.scanner_secret_key
    secret_key = query.get("secret_key")
    if SCANNER_SECRET_KEY != secret_key:
        response = "secret_key is invalid.\n"
        return HttpResponse(response)
    content_type = query.get("content_type")
    if id is None and content_type in ["certificate_request", "host"]:
        response = ""
        return HttpResponse(response)
    if id is not None and content_type == "certificate_request":
        try:
            certificate_request = CertificateRequest.objects.get(id=id)
            Scanner().scan_db_certficate(certificate_request)
            response = "Scan has been performed.\n"
            # TODOv2: return info about certificate
        except Certificate.DoesNotExist:
            response = f"Certificate with id {id} doesnt exist.\n"
    elif id is not None and content_type == "host":
        try:
            host = Host.objects.get(id=id)
            Scanner().scan_host(host)
            response = "Scan has been performed.\n"
            # TODOv2: return info about certificate
        except Certificate.DoesNotExist:
            response = f"Certificate with id {id} doesnt exist.\n"
    elif id is None and content_type == "network":
        response = "Scanning started...\n"
        celery_scan_network().delay()
    elif id is None and content_type == "certificate_requests":
        response = "Scanning started...\n"
        celery_scan_db_certificates().delay()
    elif id is None and content_type == "hosts":
        response = "Scanning started...\n"
        celery_scan_hosts().delay()
    return HttpResponse(response)


@api_view(["POST", "GET"])
def addnote(request, id):
    query = request.data or request.query_params
    note = query["note"]
    try:
        certificate_request = CertificateRequest.objects.get(id=id)
        note = Note.objects.create(
            certificate_request=certificate_request,
            text=note,
        )
        response = "Note was successfully created.\n"
    except CertificateRequest.DoesNotExist:
        response = f"Note wasn't created because certificate_request with id {id} does not exist.\n"
    return HttpResponse(response)


@api_view(["POST", "GET"])
def trackurl(request):
    query = request.data or request.query_params
    url = query["url"]
    contacts = query["contacts"]
    host, created = Host.objects.get_or_create(
        name=url,
    )
    host.contacts = contacts
    host.save()
    if created:
        response = "Network device has been created successfully.\n"
    else:
        response = "Network device with this name already exists.\n"
    return HttpResponse(response)


@api_view(["POST", "GET"])
def listcommands(request):
    commands = Command.objects.all()
    response = ""
    for command in commands:
        response += f"{command.name}\n"
    return HttpResponse(response)


@api_view(["POST", "GET"])
def get_help(request, command):
    # TODO: descriptibe help for each command
    command = Command.objects.get(name=command)
    response = f"{command.description}\n"
    return HttpResponse(response)


def get_cert_format(pem, cert_format):
    if cert_format == "json":
        json_cert = Converter(pem, "pem", "json")
        cert = json_cert.cert
    elif cert_format == "text":
        cert = Converter(pem, "pem", "text")
        cert = cert.cert
    else:
        cert = pem
    return cert


def validate_cert_format(cert_format):
    return cert_format


@api_view(["POST", "GET"])
def getcert(request, id):
    query = request.data or request.query_params
    cert_format = query.get("cert_format", "pem")
    cert_format = validate_cert_format(cert_format)
    try:
        certificate_request = CertificateRequest.objects.get(id=id)
    except CertificateRequest.DoesNotExist:
        response = f"Certificate with id {id} doesnt exist.\n"
    else:
        if certificate_request.certificate:
            pem = certificate_request.certificate
            cert = get_cert_format(pem, cert_format)
            response = f"{cert}\n"
        else:
            response = "Certificate is empty.\n"
    return HttpResponse(response)


@api_view(["POST", "GET"])
def getcacert(request):
    query = request.data or request.query_params
    cert_format = query.get("cert_format", "pem")
    pem = db_settings.ca
    cert = get_cert_format(pem, cert_format)
    response = f"{cert}\n"
    return HttpResponse(response)


@api_view(["POST", "GET"])
def getintermediarycert(request):
    query = request.data or request.query_params
    cert_format = query.get("cert_format", "pem")
    pem = db_settings.intermediary
    cert = get_cert_format(pem, cert_format)
    response = f"{cert}\n"
    return HttpResponse(response)


@api_view(["POST", "GET"])
def getcacertchain(request):
    query = request.data or request.query_params
    cert_format = query.get("cert_format", "pem")
    pem = db_settings.chain
    cert = get_cert_format(pem, cert_format)
    response = f"{cert}\n"
    return HttpResponse(response)


# @api_view(['POST', 'GET'])
# def createkeyandcsr(request):
#     return JsonResponse({})


# @api_view(['POST', 'GET'])
# def createkeyandsign(request):
#     return JsonResponse({})


# @api_view(['POST', 'GET'])
# def revokecert(request, id):
#     return JsonResponse({})


def test_mail(request):
    data = request.POST or request.GET
    if data.get('secret_key') != '69018':
        return HttpResponse('Invalid secret key')
    default_subject = 'Test Subject'
    default_message = 'Test Message'
    default_recipient_list = ''
    default_recipient_list += 'andrey.mendela@leonteq.com,'
    default_recipient_list += 'menan@leonteq.com,'
    # default_recipient_list += 'jurgeon018@gmail.com,'
    subject = data.get('subject', default_subject)
    message = data.get('message', default_message)
    recipient_list = data.get('recipient_list', default_recipient_list)
    recipient_list = recipient_list.replace('\n', '').replace(' ', '').split(',')
    try:
        recipient_list.remove('')
    except ValueError:
        pass
    from_email = db_settings.default_from_email
    fail_silently = False
    print("recipient_list", recipient_list)
    res = send_mail(subject, message, from_email, recipient_list, fail_silently)
    print(res)
    print(type(res))
    return HttpResponse("mail was sent")
