
from django.http import JsonResponse, HttpResponse, FileResponse
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view

from decouple import config

import subprocess
import requests
from datetime import timedelta
# from tempfile import gettempdir

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
    Template,
    Note,
    Command,
    Host,
)

BASE_DIR = settings.BASE_DIR
WINDOWS_SCHEMA = config('WINDOWS_SCHEMA')
WINDOWS_HOST = config('WINDOWS_HOST')
WINDOWS_PORT = config('WINDOWS_PORT')
WINDOWS_URL = f'{WINDOWS_SCHEMA}://{WINDOWS_HOST}:{WINDOWS_PORT}'



@api_view(['POST'])
def signcert(request):
    query = request.data
    files = request.FILES
    default_domain = r'CHVIRPKIPRD103.fpprod.corp\Leonteq Class 3 Issuing CA'
    default_template = 'LeonteqWebSrvManualEnroll'

    # response_format = query.get('response_format', 'file')
    requester = query.get('requester')
    template = query.get('template', default_template)
    domain = query.get('domain', default_domain)
    SAN = query.get('SAN')
    note = query.get('note')
    env = query.get('env')

    if SAN:
        SAN = SAN.replace(' ','')
    # certformat = query.get('certformat')
    # certformats = [k for k, _ in get_formats_mapper().items()]
    # if certformat not in certformats:
    #     # formats = 'pem, der, p7b, p12'
    #     formats = ', '.join(certformats)
    #     response = f"\nInvalid format. Certformat must be one of: {formats}\n"
    #     return HttpResponse(response)
    csr_file = files.get('csr')
    csr = csr_file.read().decode()
    allowed_requests = db_settings.allowed_requests
    reset_period = db_settings.reset_period
    if False:
    # if allowed_requests and reset_period:
        dt = timezone.now() - timedelta(hours=reset_period)
        certificate_requests = CertificateRequest.objects.filter(
            email=requester,
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
            return HttpResponse(response)
    templates = Template.objects.all().values_list('name', flat=True)
    if template not in templates:
        response = "Invalid template specified. List of templates you can get from here: /api/v1/listtemplates/\n"
        return HttpResponse(response)
    elif not entry_is_in_ldap(requester):
        response = f'Email "{requester}" is not in ldap.\n'
        return HttpResponse(response)
    else:
        url = f'{WINDOWS_URL}/submit'
        data = {
            "secret_key": "windows_service_69018",
            'csr': csr,
            'domain': domain,
            'template': template,
            'san': SAN,
        }
        try:
            response = requests.post(
                url,
                json=data,
                # files={
                #     'data': (None, json.dumps(data), 'application/json'),
                #     'csr': ('csr_file', csr_file, 'application/octet-stream')
                # }
            )
            status_code = response.status_code
            response = response.json()
            if status_code == 200:
                certificate = response['certificate']
                # TODO: save info about issuer, subject, notvalidafter, notvalidbefore
                certificate_request = CertificateRequest.objects.create(
                    email=requester,
                    note=note,
                    csr=csr,
                    certificate=certificate,
                    template=template,
                    domain=domain,
                )
                if note:
                    Note.objects.create(
                        certificate_request=certificate_request,
                        text=note,
                    )
                # if response_format == 'file':
                #     import os
                #     path = os.path.join(gettempdir(), 'file.cer')
                #     with open(path, 'w') as f:
                #         f.write(certificate)
                #     return FileResponse(open(path, 'rb'))
                # elif response_format == 'text':
                #     response = ''
                #     response += f'{certificate}\n'
                #     response += f'Certificate has been signed successfully. Its id is {certificate_request.id}.\n'
                #     return HttpResponse(response)
                response = ''
                response += f'{certificate}\n\n\n'
                response += f'Certificate has been signed successfully. Its id is {certificate_request.id}.\n'
                return HttpResponse(response)
            else:
                msg = response['msg']
                response = f'Certificate was not signed because of error: "{msg}". Status_code: {status_code}.\n'
                return HttpResponse(response)
        except requests.exceptions.ConnectionError as e:
            response = f'Connection error:{e}.\n'
            return HttpResponse(response)
        except Exception as e:
            response = f'Error occured. {e}. Status_code: {status_code}.\n'
            return HttpResponse(response)


def validate_cert_format(cert_format):
    return cert_format


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
