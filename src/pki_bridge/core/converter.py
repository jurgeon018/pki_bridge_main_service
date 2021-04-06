from OpenSSL import SSL, crypto
from cryptography import x509
from datetime import datetime
from cryptography.hazmat.backends import default_backend, openssl


class FunctionNotImplemented(Exception):
    pass


class Converter(object):
    '''
    converted_cert = Converter(pem, 'pem', 'cryptography_cert')
    converted_cert = Converter(pem, 'pem', 'cryptography_cert')
    cryptography_cert = converted_cert.cert
    cryptography_cert_type = converted_cert.cert_type
    cryptography_cert_format = converted_cert.cert_format
    '''

    def __init__(self, cert=None, from_=None, to=None):
        func = self.get_func(from_, to)
        if func == self.empty_cert:
            cert = func(cert, from_, to)
        else:
            cert = func(cert)
        self.cert = cert
        self.cert_format = to 
        self.cert_type = type(self.cert)
    
    # maping

    def get_formats_mapper(self):
        formats_mapper = {
            'pyopenssl_cert': {
                None: self.empty_cert,
                "cryptography_cert": self.pyopenssl_cert_to_cryptography,
                "json": self.pyopenssl_cert_to_json,
                "pem": self.pyopenssl_cert_to_pem,
                'pyopenssl_cert': self.empty_cert,
                'text': self.empty_cert,
            },
            'pem': {
                None: self.empty_cert,
                "cryptography_cert": self.pem_to_cryptography_cert,
                "pyopenssl_cert": self.pem_to_pyopenssl_cert,
                "text": self.pem_to_text,
                'json': self.pem_to_json,
                'pem': self.empty_cert,
            },
            'cryptography_cert': {
                None: self.empty_cert,
                "json": self.cryptography_cert_to_json,
                'text': self.empty_cert,
                'pem': self.empty_cert,
                'pyopenssl_cert': self.empty_cert,
                'cryptography_cert': self.empty_cert,
            },
            'text': {
                None: self.empty_cert,
                'text': self.empty_cert,
                'json': self.empty_cert,
                'pem': self.empty_cert,
                'pyopenssl_cert': self.empty_cert,
                'cryptography_cert': self.empty_cert,
            },
            'json': {
                None: self.empty_cert,
                'text': self.empty_cert,
                'json': self.empty_cert,
                'pem': self.empty_cert,
                'pyopenssl_cert': self.empty_cert,
                'cryptography_cert': self.empty_cert,
            },
            None: {
                None: self.empty_cert,
                'text': self.empty_cert,
                'json': self.empty_cert,
                'pem': self.empty_cert,
                'pyopenssl_cert': self.empty_cert,
                'cryptography_cert': self.empty_cert,
            },
        }
        openssl_formats = {
            # openssl commands
            "openssl_pem": {
                "openssl_der": self.openssl_pem_to_der,
                "openssl_p7b": self.openssl_pem_to_p7b,
                "openssl_pfx": self.openssl_pem_to_pfx,
                None: self.openssl_view_pem,
            },
            "openssl_der": {
                "openssl_pem": self.openssl_der_to_pem,
                "openssl_p7b": self.openssl_der_to_p7b,
                "openssl_pfx": self.openssl_der_to_pfx,
                None: self.openssl_view_der,
            },
            "openssl_p7b": {
                "openssl_pem": self.openssl_p7b_to_pem,
                "openssl_der": self.openssl_p7b_to_der,
                "openssl_pfx": self.openssl_p7b_to_pfx,
                None: self.openssl_view_p7b,
            },
            "openssl_pfx": {
                "openssl_pem": self.openssl_pfx_to_pem,
                "openssl_der": self.openssl_pfx_to_der,
                "openssl_p7b": self.openssl_pfx_to_p7b,
                None: self.openssl_view_pfx,
            },
        }
        formats_mapper.update(openssl_formats)
        return formats_mapper

    def get_func(self, from_, to):
        formats_mapper = self.get_formats_mapper()
        func = formats_mapper[from_][to]
        # TODO: log openssl version here.
        return func

    # convertors functions

    def pem_to_json(self, pem):
        cryptography_cert = self.pem_to_cryptography_cert(pem)
        json_cert = self.cryptography_cert_to_json(cryptography_cert)
        return json_cert

    def pyopenssl_cert_to_cryptography(self, pyopenssl_cert):
        # https://github.com/pyca/cryptography/issues/2123

        if pyopenssl_cert.__class__ is crypto.X509:
            return openssl.x509._Certificate(openssl.backend, pyopenssl_cert._x509)
        elif pyopenssl_cert.__class__ is crypto.X509Req:
            return openssl.x509._CertificateSigningRequest(
                openssl.backend, pyopenssl_cert._req)
        else:
            raise TypeError('Unknown input type: {0}'.format(pyopenssl_cert.__class__))
    
    def pem_to_cryptography_cert(self, pem):
        cryptography_cert = x509.load_pem_x509_certificate(pem.encode('utf-8'), default_backend())
        return cryptography_cert

    def pem_to_pyopenssl_cert(self, pem):    
        pyopenssl_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM,
            pem,
        )
        return pyopenssl_cert

    def pem_to_text(self, pem):
        pyopenssl_cert = self.pem_to_pyopenssl_cert(pem)
        text = crypto.dump_certificate(crypto.FILETYPE_TEXT, pyopenssl_cert)
        text = text.decode('utf-8')
        return text

    def cryptography_cert_to_json(self, cryptography_cert):
        issuer = cryptography_cert.issuer
        subject = cryptography_cert.subject
        assert issuer._attributes == issuer.rdns
        assert subject._attributes == subject.rdns
        dict_subject = self.parse_rdns(subject.rdns)
        dict_issuer = self.parse_rdns(issuer.rdns)
        dt_format = '%Y.%m.%d %H:%M:%S'
        not_valid_after = datetime.strftime(cryptography_cert.not_valid_after, dt_format)
        not_valid_before = datetime.strftime(cryptography_cert.not_valid_before, dt_format)
        cert_dict = {}
        cert_dict['subject'] = dict_subject
        cert_dict['issuer'] = dict_issuer
        cert_dict['subject']['_rfc4514'] = subject.rfc4514_string()
        cert_dict['issuer']['_rfc4514'] = issuer.rfc4514_string()
        cert_dict['not_valid_after'] = not_valid_after
        cert_dict['not_valid_before'] = not_valid_before
        cert_dict['serial_number'] = cryptography_cert.serial_number
        # cert_dict['version'] = cryptography_cert.version
        # cert_dict['public_key'] = cryptography_cert.public_key()
        # cert_dict['fingerprint'] = cryptography_cert.fingerprint
        # cert_dict['signature_algorithm_oid'] = cryptography_cert.signature_algorithm_oid
        # cert_dict['signature_hash_algorithm'] = cryptography_cert.signature_hash_algorithm
        # cert_dict['extensions'] = cryptography_cert.extensions
        # cert_dict['public_bytes'] = cryptography_cert.public_bytes()
        # cert_dict['signature'] = cryptography_cert.signature
        # cert_dict['tbs_certificate_bytes'] = cryptography_cert.tbs_certificate_bytes
        return cert_dict

    def pyopenssl_cert_to_json(self, pyopenssl_cert):
        json_cert = {}

        cert_subject = pyopenssl_cert.get_subject()
        cert_issuer = pyopenssl_cert.get_issuer()

        subject_components = dict(cert_subject.get_components())
        issuer_components = dict(cert_issuer.get_components())
        _subject_CN = subject_components[b'CN'].decode('utf-8')
        _issuer_CN = issuer_components[b'CN'].decode('utf-8')
        assert _subject_CN == cert_subject.CN
        assert _issuer_CN == cert_issuer.commonName
        # https://stackoverflow.com/questions/56763385/determine-if-ssl-certificate-is-self-signed-using-python
        json_cert['self_signed'] = _issuer_CN == _subject_CN
        json_cert['_subject_CN'] = _subject_CN
        json_cert['_subject_CN'] = _subject_CN
        json_cert['_issuer_CN'] = _issuer_CN
        json_cert['issued_to'] = cert_subject.CN
        json_cert['issued_o'] = cert_subject.O
        json_cert['issuer_c'] = cert_issuer.countryName
        json_cert['issuer_o'] = cert_issuer.organizationName
        json_cert['issuer_ou'] = cert_issuer.organizationalUnitName
        json_cert['issuer_cn'] = cert_issuer.commonName
        json_cert['cert_sn'] = str(pyopenssl_cert.get_serial_number())
        json_cert['cert_sha1'] = pyopenssl_cert.digest('sha1').decode()
        json_cert['cert_alg'] = pyopenssl_cert.get_signature_algorithm().decode()
        json_cert['cert_ver'] = pyopenssl_cert.get_version()
        json_cert['cert_sans'] = self.get_cert_sans(pyopenssl_cert)
        json_cert['cert_exp'] = pyopenssl_cert.has_expired()
        json_cert['cert_valid'] = not pyopenssl_cert.has_expired()
        # json_cert['cert_valid'] = False if pyopenssl_cert.has_expired() else True
        valid_from = datetime.strptime(pyopenssl_cert.get_notBefore().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        dt_format = '%Y-%m-%d'
        json_cert['valid_from'] = valid_from.strftime(dt_format)
        valid_till = datetime.strptime(pyopenssl_cert.get_notAfter().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        json_cert['valid_till'] = valid_till.strftime(dt_format)
        json_cert['validity_days'] = (valid_till - valid_from).days
        now = datetime.now()
        json_cert['days_left'] = (valid_till - now).days
        valid_days_to_expire = (datetime.strptime(json_cert['valid_till'], dt_format) - datetime.now()).days
        json_cert['valid_days_to_expire'] = valid_days_to_expire
        return json_cert

    def pyopenssl_cert_to_pem(self, pyopenssl_cert):
        # https://stackoverflow.com/questions/9796694/pyopenssl-convert-certificate-object-to-pem-file
        # req = crypto.X509Req()
        # pkey = crypto.PKey()
        # pkey.generate_key(crypto.TYPE_RSA, 2048)
        # req.set_pubkey(pkey)
        # req.sign(pkey, 'sha1')
        # certreq = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        # certreq = certreq.replace('-----BEGIN CERTIFICATE REQUEST-----\n', '').replace('-----END CERTIFICATE REQUEST-----\n', '')
        # private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
        pem = crypto.dump_certificate(crypto.FILETYPE_PEM, pyopenssl_cert)
        pem = pem.decode('utf-8').strip()
        return pem

    def empty_cert(self, cert, from_, to):
        raise FunctionNotImplemented(f"Cannot convert from '{from_}' to '{to}'")
        return "Not Implemented"
        return None

    # utils

    def parse_rdns(self, rdns):
        result = {}
        for rdn in rdns:
            # _attribute_set is always a list with 1 element
            attribute = list(rdn._attribute_set)[0]
            rdn_rfc4514 = rdn.rfc4514_string().split('=')
            code = rdn_rfc4514[0].replace(' ', '')
            rdn_value = rdn_rfc4514[-1].replace(' ', '')
            value = attribute.value.replace(' ', '')
            name = attribute.oid._name.replace(' ', '')
            assert rdn_value == value
            result[name] = {
                "code": code,
                "value": value,
            }
        return result

    def get_cert_sans(self, x509cert):
        san = ''
        ext_count = x509cert.get_extension_count()
        for i in range(0, ext_count):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
        san = san.replace(',', ';')
        return san

    # TODO: openssl terminal commands

    # https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/
    # https://knowledge.digicert.com/solution/SO26449.html
    # https://www.sslshopper.com/article-most-common-openssl-commands.html

    # PEM, Base64 ASCII(.pem, .crt, .cer, .key, .ca-bundle, .....)
    # DER, binary(.der, .cer)
    # PKCS #12 (.pfx, .pfx)
    # PKCS #7 (.p7b)

    def validate_cert_format(self, cert_format):
        if cert_format is None:
            return cert_format
        pem_formats = [
            "pem",
            "PEM",
            'base64',
            'BASE64',
        ]
        der_formats = [
            'der',
            'DER',
            'binary',
            'BINARY',
        ]
        p7b_formats = [
            'p7b',
            'P7B',
            'p7c',
            'P7C',
        ]
        pfx_formats = [
            'pfx',
            'PFX',
            'p12',
            'P12',
        ]
        if cert_format in pem_formats:
            cert_format = 'pem'
        elif cert_format in der_formats:
            cert_format = 'der'
        elif cert_format in p7b_formats:
            cert_format = 'p7b'
        elif cert_format in pfx_formats:
            cert_format = 'pfx'
        else:
            msg = 'Invalid format of "cert_format".'
            return msg
        return cert_format

    # ***

    def openssl_pem_to_der(self, x=None, hello="ss", *args, **kwargs):
        # openssl x509 -outform der -in www.ssl.com.pem -out www.ssl.com.der
        # openssl x509 -outform der -inform pem -in www.ssl.com.pem -out www.ssl.com.der
        outform = 'der'
        inform = 'pem'
        in_ = 'www.ssl.com.pem'
        out = 'www.ssl.com.der'
        # command = f'openssl x509 -outform {outform} -in {in_} -out {out}'
        command = f'openssl x509 -outform {outform} -inform {inform} -in {in_} -out {out}'
        return command

    def openssl_pem_to_p7b(self, *args, **kwargs):
        # openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
        # openssl crl2pkcs7 -nocrl -certfile CERTIFICATE.pem -certfile MORE.pem -out CERTIFICATE.p7b
        certfile1 = 'CERTIFICATE.pem'
        certfile2 = 'MORE.pem'
        out = 'CERTIFICATE.p7b'
        command = f'openssl crl2pkcs7 -nocrl -certfile {certfile1} -certfile {certfile2} -out {out}'
        return command

    def openssl_pem_to_pfx(self, *args, **kwargs):
        # openssl pkcs12 -export -out certificate.pfx -inkey privateKey.key -in certificate.crt -certfile CACert.crt
        out = 'certificate.pfx'
        inkey = 'privateKey.key'
        in_ = 'certificate.crt'
        certfile = 'CACert.crt'
        command = f'openssl pkcs12 -export -out {out} -inkey {inkey} -in {in_} -certfile {certfile}'
        return command

    def openssl_view_pem(self, in_, *args, **kwargs):
        # openssl x509 -in www.ssl.com.pem -text -noout 
        # in_ = 'www.ssl.com.pem'
        command = f'openssl x509 -in {in_} -text -noout'
        return command

    def openssl_der_to_pem(self, *args, **kwargs):
        # openssl x509 -inform der -in www.ssl.com.der -out www.ssl.com.pem
        # openssl x509 -inform der -in www.ssl.com.der -outform pem -out www.ssl.com.pem
        inform = 'der'
        outform = 'pem'
        in_ = 'www.ssl.com.der'
        out = 'www.ssl.com.pem'
        # command = f'openssl x509 -inform {inform} -in {in_} -out {out}'
        command = f'openssl x509 -inform {inform} -in {in_} -outform {outform} -out {out}'
        return command

    def openssl_der_to_p7b(self, *args, **kwargs):
        raise FunctionNotImplemented('Function "der_to_p7b" is not implemented.')

    def openssl_der_to_pfx(self, *args, **kwargs):
        raise FunctionNotImplemented('Function "der_to_pfx" is not implemented.')

    def openssl_view_der(self, *args, **kwargs):
        # openssl x509 -inform der -in www.ssl.com.der -text -noout
        in_ = 'www.ssl.com.der'
        inform = 'der'
        command = f'openssl x509 -inform {inform} -in {in_} -text -noout'
        return command

    def openssl_p7b_to_pem(self, *args, **kwargs):
        # openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
        in_ = 'certificatename.p7b'
        out = 'certificatename.pem'
        command = f'openssl pkcs7 -print_certs -in {in_} -out {out}'
        return command

    def openssl_p7b_to_der(self, *args, **kwargs):
        raise FunctionNotImplemented('Function "p7b_to_der" is not implemented.')

    def openssl_p7b_to_pfx(self, *args, **kwargs):
        # P7B -> PFX
        # STEP 1: P7B -> CER
        # openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
        # STEP 2: CER -> Private Key to PFX
        # openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
        raise FunctionNotImplemented('Function "p7b_to_pfx" is not implemented.')

    def openssl_view_p7b(self, *args, **kwargs):
        raise FunctionNotImplemented('Function "view_p7b" is not implemented.')

    def openssl_pfx_to_pem(self, in_, out, *args, **kwargs):
        # openssl pkcs12 -in certificatename.pfx -out certificatename.pem
        # openssl pkcs12 -in keyStore.pfx -out keyStore.pem -nodes
        # in_ = 'keyStore.pfx'
        # out = 'keyStore.pem'
        # command = f'openssl pkcs12 -in {in_} -out {out}'
        command = f'openssl pkcs12 -in {in_} -out {out} -nodes'
        return command

    def openssl_pfx_to_der(self, *args, **kwargs):
        raise FunctionNotImplemented('Function "pfx_to_der" is not implemented.')

    def openssl_pfx_to_p7b(self, *args, **kwargs):
        raise FunctionNotImplemented('Function "pfx_to_p7b" is not implemented.')

    def openssl_view_pfx(self, *args, **kwargs):
        raise FunctionNotImplemented('Function "view_pfx" is not implemented.')

    def openssl_x509_to_pem(self, from_, to_):
        # openssl x509 -in www.ssl.com.x509 -outform PEM -out www.ssl.com3.pem
        in_ = 'www.ssl.com.x509'
        out_ = 'www.ssl.com3.pem'
        outform = 'PEM'
        command = f'openssl x509 -in {in_} -outform {outform} -out {out_}'
        return command

    def openssl_pfx_to_pk8(self, from_, to_):
        # PFX -> PKCS#8
        # STEP 1: PFX -> PEM
        # openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
        # STEP 2: PEM -> PKCS8
        # openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
        return 'Not implemented.'



