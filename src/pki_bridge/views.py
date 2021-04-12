
from django.http import JsonResponse, HttpResponse, FileResponse
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view
import OpenSSL
from decouple import config

import requests
from datetime import timedelta
from tempfile import gettempdir

from pki_bridge.tasks import (
    celery_scan_network,
    celery_scan_hosts,
    celery_scan_db_certificates,
)
from pki_bridge.core.scanner import Scanner
from pki_bridge.core.utils import get_obj_admin_link
from pki_bridge.core.converter import Converter
from pki_bridge.conf import db_settings
from pki_bridge.core.views import (
    build_templates_string,
)
from pki_bridge.core.ldap import (
    entry_is_in_ldap,
)
from pki_bridge.management import (
    update_templates,
)
from pki_bridge.models import (
    CertificateRequest,
    Certificate,
    Template,
    Note,
    Command,
    Host,
    Requester,
    ProjectUser,
)
import urllib3
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BASE_DIR = settings.BASE_DIR
WINDOWS_SECRET_KEY = "windows_service_69018"
WINDOWS_SCHEMA = config('WINDOWS_SCHEMA')
WINDOWS_HOST = config('WINDOWS_HOST')
WINDOWS_PORT = config('WINDOWS_PORT')
WINDOWS_URL = f'{WINDOWS_SCHEMA}://{WINDOWS_HOST}:{WINDOWS_PORT}'


def throttle_request(requester):
    allowed_requests = db_settings.allowed_requests
    reset_period = db_settings.reset_period
    if allowed_requests and reset_period:
        dt = timezone.now() - timedelta(hours=reset_period)
        certificate_requests = CertificateRequest.objects.filter(
            requester__email=requester,
            created__gte=dt,
        ).order_by('created')
        last_request = certificate_requests.last()
        if certificate_requests.count() > db_settings.allowed_requests:
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
        SAN = SAN.replace(' ','')
    return SAN


def validate_template_rights(requester_email, password, template):
    if not db_settings.enable_template_rights_validation:
        return None
    user = ProjectUser.objects.filter(email=requester_email).first()
    templates = user.templates.all().values_list('name', flat=True)
    if user is not None:
        if not user.check_password(password):
            response = 'Password is incorrect'
        elif template not in templates:
            response = 'You do not have rights to use this template.\n'
        return response


def create_certificate_request(pem, requester_email, template, domain, SAN, csr, query):
    note = query.get('note', 'true')
    enable_sending_certificate_to_mail = query.get('enable_sending_certificate_to_mail', 'true')
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
    if enable_sending_certificate_to_mail == 'true':
        send_certificate_to_mail(requester_email, certificate_request)
    return certificate_request


def get_intermediary_response(csr, domain, template, SAN):
    try:
        data = {
            "secret_key":  WINDOWS_SECRET_KEY,
            'csr': csr,
            'domain': domain,
            'template': template,
            'san': SAN,
        }
        response = requests.post(
            f'{WINDOWS_URL}/submit',
            verify=False,
            json=data,
            # files={
            #     'data': (None, json.dumps(data), 'application/json'),
            #     'csr': ('csr_file', csr_file, 'application/octet-stream')
            # }
        )
        response = response.json()
    except requests.exceptions.ConnectionError as e:
        if settings.DEBUG and settings.MOCK_INTERMEDIARY_RESPONSE:
            test_cert_filepath = BASE_DIR / 'fixtures' / 'test_certificate.pem'
            with open(test_cert_filepath, 'r', encoding='utf-8') as cert_file:
                response = {
                    'certificate': cert_file.read()
                }
        else:
            response = f'Cannot connect to intermediary.\n{e}.\n'
    except Exception as e:
        response = f'Error occured. {e}. \n'
    return response


@api_view(['POST'])
def signcert(request):
    default_domain = r'CHVIRPKIPRD103.fpprod.corp\Leonteq Class 3 Issuing CA'
    default_template = 'LeonteqWebSrvManualEnroll'

    query = request.data
    files = request.FILES

    requester_email = query['requester']
    password = query.get('password')
    response_format = query.get('response_format', 'text')
    template = query.get('template', default_template)
    domain = query.get('domain', default_domain)
    note = query.get('note')
    SAN = query.get('SAN')
    # env = query.get('env')
    # certformat = query.get('certformat', 'pem')
    csr_file = files.get('csr')
    csr = csr_file.read().decode()
    SAN = validate_SAN(SAN)

    # certformat_invalid_msg = validate_certformat(certformat)
    # if certformat_invalid_msg is not None:
    #     return HttpResponse(certformat_invalid_msg, status=400)

    throttling_result = throttle_request(requester_email)
    if throttling_result is not None:
        return HttpResponse(throttling_result, status=403)

    template_rigths_result = validate_template_rights(requester_email, password, template)
    if template_rigths_result is not None:
        return HttpResponse(template_rigths_result, status=400)

    templates = Template.objects.all().values_list('name', flat=True)
    if template not in templates and not db_settings.allow_any_template:
        response = "Invalid template specified. List of templates you can get from here: /api/v1/listtemplates/\n"
        return HttpResponse(response, status=400)

    if not entry_is_in_ldap(requester_email):
        response = f'Email "{requester_email}" is not in ldap.\n'
        return HttpResponse(response, status=403)

    intermediary_response = get_intermediary_response(csr, domain, template, SAN)
    try:
        pem = intermediary_response['certificate']
    except Exception as e:
        return HttpResponse(intermediary_response, status=500)
    try:
        certificate_request = create_certificate_request(
            pem, requester_email, template, 
            domain, SAN, csr, query,
        )
    except OpenSSL.crypto.Error as e:
        response = f'Error: {e}'
        return HttpResponse(response, status=500)
    if response_format == 'text':
        response = ''
        response += f'{pem}\n\n\n'
        response += f'Certificate request has been signed successfully. '
        response += f'Its id is {certificate_request.id}.\n'
        response += f'Certificate has been sent to your email in pem format.\n'
        return HttpResponse(response, status=200)
    elif response_format == 'file':
        # TODO v2: return response as file
        # return signcert_file_response(pem)
        return HttpResponse(f'Response format {response_format} is not implemented.\n', status=400)
    else:
        return HttpResponse(f'Response format {response_format} is not implemented.\n', status=400)


def send_certificate_to_mail(requester_email, certificate_request):
    subject = f'Certificate request #{certificate_request.id}'
    message = f''
    message += f'Certificate request id: {certificate_request.id}\n'
    message += f'Certificate id: {certificate_request.certificate.id}\n'
    message += f'Certificate request link: {get_obj_admin_link(certificate_request)}\n'
    message += f'Certificate link: {get_obj_admin_link(certificate_request.certificate)}\n'
    message += f'Certificate pem: \n{certificate_request.certificate.pem}\n'
    message += f'CSR: \n{certificate_request.csr}\n'
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = []
    recipient_list.append(requester_email)
    # recipient_list.append('andrey.mendela@leonteq.com')
    send_mail(
        subject=subject,
        message=message,
        from_email=from_email,
        recipient_list=recipient_list,
        fail_silently=False
    )


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
#     return FileResponse(open(path, 'rb'))



@api_view(['POST', 'GET'])
def listtemplates(request):
    if db_settings.update_templates_from_ca:
        update_templates()
    response = build_templates_string()
    return HttpResponse(response)


@api_view(['POST', 'GET'])
def pingca(request):
    url = f'{WINDOWS_URL}/pingca'
    response = requests.get(url)
    return HttpResponse(response)


@api_view(['POST', 'GET'])
def run_scanner_view(request, id=None):
    # TODO v2: block next request to run_scanner_view untill scan session has finished
    if request.method == 'POST':
        query = request.data
    elif request.method == 'GET':
        query = request.query_params
    SCANNER_SECRET_KEY = db_settings.scanner_secret_key
    secret_key = query.get('secret_key')
    if SCANNER_SECRET_KEY != secret_key:
        response = f'secret_key is invalid.\n'
        return HttpResponse(response)
    content_type = query.get('content_type')
    if id is None and content_type in ['certificate_request', 'host']:
        response = ''
        return HttpResponse(response)
    if id is not None and content_type == 'certificate_request':
        try:
            certificate_request = CertificateRequest.objects.get(id=id)
            Scanner().scan_db_certficate(certificate_request)
            response = 'Scan has been performed.\n'
            # TODOv2: return info about certificate
        except Certificate.DoesNotExist:
            response = f'Certificate with id {id} doesnt exist.\n'
    elif id is not None and content_type == 'host':
        try:
            host = Host.objects.get(id=id)
            Scanner().scan_host(host)
            response = 'Scan has been performed.\n'
            # TODOv2: return info about certificate
        except Certificate.DoesNotExist:
            response = f'Certificate with id {id} doesnt exist.\n'
    elif id is None and content_type == 'network':
        response = 'Scanning started...\n'
        celery_scan_network().delay()
    elif id is None and content_type == 'certificate_requests':
        response = 'Scanning started...\n'
        celery_scan_db_certificates().delay()
    elif id is None and content_type == 'hosts':
        response = 'Scanning started...\n'
        celery_scan_hosts().delay()
    return HttpResponse(response)


@api_view(['POST', 'GET'])
def addnote(request, id):
    query = request.data
    note = query['note']
    try:
        certificate_request = CertificateRequest.objects.get(id=id)
        note = Note.objects.create(
            certificate_request=certificate_request,
            text=note,
        )
        response = 'Note was successfully created.\n'
    except CertificateRequest.DoesNotExist:
        response = f"Note wasn't created because certificate_request with id {id} does not exist.\n"
    return HttpResponse(response)


@api_view(['POST', 'GET'])
def trackurl(request):
    query = request.data
    url = query['url']
    contacts = query['contacts']
    network_device, created = Host.objects.get_or_create(
        url=url,
    )
    network_device.contacts = contacts
    network_device.save()
    if created:
        response = 'Network device has been created successfully.\n'
    else:
        response = 'Network device with this name already exists.\n'
    return HttpResponse(response)


@api_view(['POST', 'GET'])
def listcommands(request):
    commands = Command.objects.all()
    response = ''
    for command in commands:
        response += f'{command.name}\n'
    return HttpResponse(response)


@api_view(['POST', 'GET'])
def get_help(request, command):
    command = Command.objects.get(name=command)
    response = f'{command.description}\n'
    return HttpResponse(response)


def get_cert_format(pem, cert_format):
    if cert_format == 'json':
        json_cert = Converter(pem, 'pem', 'json')
        cert = json_cert.cert
    elif cert_format == 'text':
        cert = Converter(pem, 'pem', 'text')
        cert = cert.cert
    else:
        cert = pem
    return cert


def validate_cert_format(cert_format):
    return cert_format


@api_view(['POST', 'GET'])
def getcert(request, id):
    query = request.data or request.query_params
    cert_format = query.get('cert_format', 'pem')
    cert_format = validate_cert_format(cert_format)
    try:
        certificate_request = CertificateRequest.objects.get(id=id)
    except CertificateRequest.DoesNotExist:
        response = f'Certificate with id {id} doesnt exist.\n'
    else:
        if certificate_request.certificate:
            pem = certificate_request.certificate
            cert = get_cert_format(pem, cert_format)
            response = f'{cert}\n'
        else:
            response = 'Certificate is empty.\n'
    return HttpResponse(response)


@api_view(['POST', 'GET'])
def getcacert(request):
    query = request.data or request.query_params
    cert_format = query.get('cert_format', 'pem')
    pem = db_settings.ca
    cert = get_cert_format(pem, cert_format)
    response = f'{cert}\n'
    return HttpResponse(response)


@api_view(['POST', 'GET'])
def getintermediarycert(request):
    query = request.data or request.query_params
    cert_format = query.get('cert_format', 'pem')
    pem = db_settings.intermediary
    cert = get_cert_format(pem, cert_format)
    response = f'{cert}\n'
    return HttpResponse(response)


@api_view(['POST', 'GET'])
def getcacertchain(request):
    query = request.data or request.query_params
    cert_format = query.get('cert_format', 'pem')
    pem = db_settings.chain
    cert = get_cert_format(pem, cert_format)
    response = f'{cert}\n'
    return HttpResponse(response)


@api_view(['POST', 'GET'])
def createkeyandcsr(request):
    return JsonResponse({})


@api_view(['POST', 'GET'])
def createkeyandsign(request):
    return JsonResponse({})


@api_view(['POST', 'GET'])
def revokecert(request, id):
    return JsonResponse({})


def test_mail(request):
    res = send_mail(
        'Test mail.',
        'Test mail.',
        settings.DEFAULT_FROM_EMAIL,
        [
            'jurgeon018@gmail.com',
            'andrey.mendela@leonteq.com',
            'menan@leonteq.com',
        ],
        fail_silently=False
    )
    print(res)
    print(type(res))
    return HttpResponse('mail was sent')
