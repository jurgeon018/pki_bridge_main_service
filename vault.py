import requests
import json

def build_data():
    # data = {}
    # csr = 'test csr'
    # common_name = 'vault-dev.fpprod.corp'
    # data = {
    #     'csr': csr,
    #     'common_name': common_name,
    #     'format': 'pem',
    #     # '': '',
    # }
    with open('payload.json') as f:
        payload = json.load(f)
    data = payload
    return data

def build_headers():
    root_token = 's.ucvE1OzSrNlceMex9MYS8FU5'
    client_token = '???'
    # token = client_token
    token = root_token
    headers = {
        'X-Vault-Token': token,
    }
    return headers

def build_url():
    # url = 'https://vault-dev.fpprod.corp/v1/pki_intca/issue/fpprodcorp'
    url = 'https://vault-dev.fpprod.corp/v1/pki_intca/sign/fpprodcorp'
    return url
    # # name = 'svc-certreq-prd'
    # # name = 'fpprodcorp'
    # # name = 'pki_intca'
    # name = 'fpprod'
    # # url = f'http://vault-dev.fpprod.corp/v1/pki/crl/rotate'
    # url = f'http://vault-dev.fpprod.corp/v1/pki/sign/{name}'
    # return url

response = requests.post(
    url=build_url(),
    json=build_data(),
    headers=build_headers(),
    verify=False,
)
print(response.status_code)
# import pprint
res = response.json()
if response.status_code == 400:
    print(res)
else:
    request_id = res['request_id']
    lease_id = res['lease_id']
    renewable = res['renewable']
    lease_duration = res['lease_duration']
    wrap_info = res['wrap_info']
    warnings = res['warnings']
    auth = res['auth']
    data = res['data']
    ca_chain = data['ca_chain']
    certificate = data['certificate']
    expiration = data['expiration']
    issuing_ca = data['issuing_ca']
    private_key = data['private_key']
    private_key_type = data['private_key_type']
    serial_number = data['serial_number']
    print("request_id: ", request_id)
    print("lease_id: ", lease_id)
    print("renewable: ", renewable)
    print("lease_duration: ", lease_duration)
    print("wrap_info: ", wrap_info)
    print("warnings: ", warnings)
    print("auth: ", auth)
    print("expiration: ", expiration)
    print("private_key_type: ", private_key_type)
    print("serial_number: ", serial_number)
    # print("ca_chain: ", ca_chain)
    # print("certificate: ", certificate)
    # print("issuing_ca: ", issuing_ca)
    # print("private_key: ", private_key)
    from OpenSSL import crypto
    pyopenssl_cert = crypto.load_certificate(
        crypto.FILETYPE_PEM,
        certificate,
    )
    print(vars(pyopenssl_cert))
    text = crypto.dump_certificate(crypto.FILETYPE_TEXT, pyopenssl_cert)
    text = text.decode("utf-8")
    # print(text)
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.backends import openssl
    cryptography_cert = x509.load_pem_x509_certificate(certificate.encode("utf-8"), default_backend())
    # print(vars(cryptography_cert))

'''
https://www.hashicorp.com/blog/certificate-management-with-vault

https://www.vaultproject.io/docs/concepts/tokens
https://www.vaultproject.io/docs/concepts/auth

https://www.vaultproject.io/docs/commands/token/create
https://www.vaultproject.io/docs/auth/token

https://www.vaultproject.io/api/auth/token
https://www.vaultproject.io/api-docs/secret/pki#sign-certificate


curl \
--header "X-Vault-Token: s.ucvE1OzSrNlceMex9MYS8FU5" \
--request POST \
--insecure \
--data @payload.json \
https:/vault-dev.fpprod.corp/v1/pki_intca/sign/fpprodcorp

'''