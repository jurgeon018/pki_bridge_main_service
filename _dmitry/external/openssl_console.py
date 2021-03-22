import os
import subprocess
import tempfile


CSR_STORE_DIR = tempfile.gettempdir()
CERT_STORE_DIR = tempfile.gettempdir()
ROOT_CA_PEM_PATH = "./config/root_certificate/rootCA.pem"
ROOT_CA_KEY_PATH = "./config/root_certificate/rootCA.key"
OPENSSL_PATH = "openssl"


def submit(csr):
    csr_filepath = os.path.join(CSR_STORE_DIR, "csr.req")
    with open(csr_filepath, 'w') as csr_file:
        csr_file.write(csr)
        csr_file.close()

    cert_filepath = os.path.join(CERT_STORE_DIR, "csr.cer")
    run_args = [OPENSSL_PATH, 'x509', '-req', '-in', csr_filepath,
                '-CA', ROOT_CA_PEM_PATH, '-CAkey', ROOT_CA_KEY_PATH,
                '-CAcreateserial', '-days', '365',
                '-out', cert_filepath]
    subprocess.run(run_args)

    result_cert = None
    with open(cert_filepath, 'r', encoding='utf-8') as cert_file:
        result_cert = cert_file.readlines()
        cert_file.close()

    return {'result': result_cert}
