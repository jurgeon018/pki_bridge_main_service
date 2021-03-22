# https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/
# https://knowledge.digicert.com/solution/SO26449.html
# https://www.sslshopper.com/article-most-common-openssl-commands.html

# PEM, Base64 ASCII(.pem, .crt, .cer, .key, .ca-bundle, .....)
# DER, binary(.der, .cer)
# PKCS #12 (.pfx, .pfx)
# PKCS #7 (.p7b)


class FunctionNotImplemented(Exception):
    pass


def get_formats_mapper():
    formats_mapper = {
        "pem": {
            "der": pem_to_der,
            "p7b": pem_to_p7b,
            "pfx": pem_to_pfx,
            None: view_pem,
        },
        "der": {
            "pem": der_to_pem,
            "p7b": der_to_p7b,
            "pfx": der_to_pfx,
            None: view_der,
        },
        "p7b": {
            "pem": p7b_to_pem,
            "der": p7b_to_der,
            "pfx": p7b_to_pfx,
            None: view_p7b,
        },
        "pfx": {
            "pem": pfx_to_pem,
            "der": pfx_to_der,
            "p7b": pfx_to_p7b,
            None: view_pfx,
        },
    }
    return formats_mapper


def get_openssl_func(from_, to_=None):
    from_ = validate_cert_format(from_)
    to_ = validate_cert_format(to_)
    formats_mapper = get_formats_mapper()
    func = formats_mapper[from_][to_]
    # TODO: log openssl version here.
    return func


def validate_cert_format(cert_format):
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


def pem_to_der(x=None, hello="ss", *args, **kwargs):
    # openssl x509 -outform der -in www.ssl.com.pem -out www.ssl.com.der
    # openssl x509 -outform der -inform pem -in www.ssl.com.pem -out www.ssl.com.der
    outform = 'der'
    inform = 'pem'
    in_ = 'www.ssl.com.pem'
    out = 'www.ssl.com.der'
    # command = f'openssl x509 -outform {outform} -in {in_} -out {out}'
    command = f'openssl x509 -outform {outform} -inform {inform} -in {in_} -out {out}'
    return command


def pem_to_p7b(*args, **kwargs):
    # openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
    # openssl crl2pkcs7 -nocrl -certfile CERTIFICATE.pem -certfile MORE.pem -out CERTIFICATE.p7b
    certfile1 = 'CERTIFICATE.pem'
    certfile2 = 'MORE.pem'
    out = 'CERTIFICATE.p7b'
    command = f'openssl crl2pkcs7 -nocrl -certfile {certfile1} -certfile {certfile2} -out {out}'
    return command


def pem_to_pfx(*args, **kwargs):
    # openssl pkcs12 -export -out certificate.pfx -inkey privateKey.key -in certificate.crt -certfile CACert.crt
    out = 'certificate.pfx'
    inkey = 'privateKey.key'
    in_ = 'certificate.crt'
    certfile = 'CACert.crt'
    command = f'openssl pkcs12 -export -out {out} -inkey {inkey} -in {in_} -certfile {certfile}'
    return command


def view_pem(in_, *args, **kwargs):
    # openssl x509 -in www.ssl.com.pem -text -noout 
    # in_ = 'www.ssl.com.pem'
    command = f'openssl x509 -in {in_} -text -noout'
    return command


def der_to_pem(*args, **kwargs):
    # openssl x509 -inform der -in www.ssl.com.der -out www.ssl.com.pem
    # openssl x509 -inform der -in www.ssl.com.der -outform pem -out www.ssl.com.pem
    inform = 'der'
    outform = 'pem'
    in_ = 'www.ssl.com.der'
    out = 'www.ssl.com.pem'
    # command = f'openssl x509 -inform {inform} -in {in_} -out {out}'
    command = f'openssl x509 -inform {inform} -in {in_} -outform {outform} -out {out}'
    return command


def der_to_p7b(*args, **kwargs):
    raise FunctionNotImplemented('Function "der_to_p7b" is not implemented.')


def der_to_pfx(*args, **kwargs):
    raise FunctionNotImplemented('Function "der_to_pfx" is not implemented.')


def view_der(*args, **kwargs):
    # openssl x509 -inform der -in www.ssl.com.der -text -noout
    in_ = 'www.ssl.com.der'
    inform = 'der'
    command = f'openssl x509 -inform {inform} -in {in_} -text -noout'
    return command


def p7b_to_pem(*args, **kwargs):
    # openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
    in_ = 'certificatename.p7b'
    out = 'certificatename.pem'
    command = f'openssl pkcs7 -print_certs -in {in_} -out {out}'
    return command


def p7b_to_der(*args, **kwargs):
    raise FunctionNotImplemented('Function "p7b_to_der" is not implemented.')


def p7b_to_pfx(*args, **kwargs):
    # P7B -> PFX
    # STEP 1: P7B -> CER
    # openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
    # STEP 2: CER -> Private Key to PFX
    # openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
    raise FunctionNotImplemented('Function "p7b_to_pfx" is not implemented.')


def view_p7b(*args, **kwargs):
    raise FunctionNotImplemented('Function "view_p7b" is not implemented.')


def pfx_to_pem(in_, out, *args, **kwargs):
    # openssl pkcs12 -in certificatename.pfx -out certificatename.pem
    # openssl pkcs12 -in keyStore.pfx -out keyStore.pem -nodes
    # in_ = 'keyStore.pfx'
    # out = 'keyStore.pem'
    # command = f'openssl pkcs12 -in {in_} -out {out}'
    command = f'openssl pkcs12 -in {in_} -out {out} -nodes'
    return command


def pfx_to_der(*args, **kwargs):
    raise FunctionNotImplemented('Function "pfx_to_der" is not implemented.')


def pfx_to_p7b(*args, **kwargs):
    raise FunctionNotImplemented('Function "pfx_to_p7b" is not implemented.')


def view_pfx(*args, **kwargs):
    raise FunctionNotImplemented('Function "view_pfx" is not implemented.')


def x509_to_pem(from_, to_):
    # openssl x509 -in www.ssl.com.x509 -outform PEM -out www.ssl.com3.pem
    in_ = 'www.ssl.com.x509'
    out_ = 'www.ssl.com3.pem'
    outform = 'PEM'
    command = f'openssl x509 -in {in_} -outform {outform} -out {out_}'
    return command


def pfx_to_pk8(from_, to_):
    # PFX -> PKCS#8
    # STEP 1: PFX -> PEM
    # openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
    # STEP 2: PEM -> PKCS8
    # openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
    return 'Not implemented.'



