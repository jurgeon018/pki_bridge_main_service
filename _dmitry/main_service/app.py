import db.secrets as secrets
import hvac
import logging
import psycopg2
import os
import logging as log
import subprocess
import tempfile
import requests
import urllib.parse
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from psycopg2.extras import DictCursor

import config

from flask import Flask, jsonify, request, current_app as app
from marshmallow import ValidationError, Schema, fields, validate


app = Flask(__name__)


# endpoints

# /csr/
# /csr/<int:csr_id>
# /certificate/
# /certificate/<int:certificate_id>/cer
# /certificate/<int:certificate_id>/pem
# /certificate/<int:certificate_id>/revocation
# /certificate/<int:certificate_id>/hold
# /certificate/<int:certificate_id>/approvecsr
# /task/cleaning-certificate
# /task/remembercertificate



@app.route("/csr/", methods=['POST'])
def csr():
    prefix_err_msg = "cannot submit CSR"
    try:
        body = request.json
        body_fields = CSRCreateSchema().load(body)

        sql = "INSERT INTO csr(request, kind) VALUES(%s, %s) RETURNING id;"
        result = execute_fetchone(app.db, sql, (body_fields['request'], body_fields['kind']))

        send(config.csr('wildcard', 'approve_from_email'), config.csr('wildcard', 'approve_to_email'),
                  "Approve wildcard CSR",
                  config.csr('wildcard', 'approve_message') % (result['id']))

        return jsonify({'id': result['id'], 'request': body_fields['request'], 'kind': body_fields['kind']})
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400
    except Exception:
        log.exception(prefix_err_msg)
        return jsonify({'error': prefix_err_msg}), 500


@app.route("/csr/<int:csr_id>", methods=['PATCH'])
def csr_id(csr_id):
    prefix_err_msg = "cannot submit CSR"
    try:
        body = request.json
        body_fields = CSRSetStatusSchema().load(body)

        sql = "UPDATE csr SET status=%s, updated_at=NOW() WHERE id=%s"
        execute(app.db, sql, (body_fields['status'], csr_id))

        return jsonify({'id': csr_id, 'status': body_fields['status']})
    except Exception:
        log.exception(prefix_err_msg)
        return jsonify({'error': prefix_err_msg}), 500


@app.route('/certificate/', methods=['POST'])
def certificate():

    def request_attributes(request):
        DATA_STORE_DIR = tempfile.gettempdir()
        CERT_STORE_DIR = tempfile.gettempdir()
        OPENSSL_PATH = "openssl"
        csr_filepath = os.path.join(DATA_STORE_DIR, "csr.req")
        with open(csr_filepath, 'w') as csr_file:
            csr_file.write(request)
            csr_file.close()

        result_filepath = os.path.join(DATA_STORE_DIR, "csr_info.txt")
        run_args = [OPENSSL_PATH, 'req', '-out', result_filepath, '-text', '-in', csr_filepath]
        subprocess.run(run_args)

        with open(result_filepath, 'r', encoding='utf-8') as result_file:
            result_lines = result_file.readlines()
            for line in result_lines:
                index = line.find("Subject: ")
                if index != -1:
                    attributes_str = line[index:]
                    attributes = attributes_str.split(",")
                    result = {}
                    for a in attributes:
                        a_parts = a.split("=")
                        a_parts = [p.strip() for p in a_parts]
                        result[a_parts[0]] = a_parts[1]

                result_file.close()

        return result

    def submit(template_name, domain, request):
        CSR_STORE_DIR = tempfile.gettempdir()
        CERT_STORE_DIR = tempfile.gettempdir()
        CERTREQ_PATH = "certreq"
        csr_filepath = os.path.join(CSR_STORE_DIR, "csr.req")
        with open(csr_filepath, 'w') as csr_file:
            csr_file.write(str(request))
            csr_file.close()

        cert_filepath = os.path.join(CERT_STORE_DIR, "csr.cer")

        run_args = [CERTREQ_PATH]
        run_args += config.template(template_name, 'Attributes').split('  ')
        run_args += ['-submit', '-f', '-q', '-config', domain, csr_filepath, cert_filepath]
        subprocess.run(run_args)
        logging.debug("certreq run OK")

        result_cert = None
        with open(cert_filepath, 'r', encoding='utf-8') as cert_file:
            result_cert = cert_file.readlines()
            cert_file.close()
        logging.debug("certreq read output OK")

        return {'result': result_cert}

    prefix_err_msg = "cannot submit CSR through windows service"
    try:
        body = request.json
        body_fields = CertificateCreateSchema().load(body)

        if len(lookup(app.db, email=body_fields['email'])) < 1:
            group = config.ldap('main', 'group')
            username = config.ldap('main', 'username')
            password = config.ldap('main', 'password')
            search_output = search_run(group=group, ldap_username=username, ldap_password=password,
                                                       attributes=['sAMAccountName', 'mail'])
            search_res = search_output_parse(search_output.split('\n'))
            was_found = False
            for s in search_res:
                if s['mail'] == body_fields['email']:
                    was_found = True
                    break

            if not was_found:
                raise ValueError("email is not found in LDAP")

        csr = body_fields['request']
        attributes = request_attributes(csr)
        cn = ""
        if 'CN' in attributes:
            cn = attributes['CN']

        template_name = body_fields['template']
        domain = body_fields['domain']

        json_result = {}
        if cn.find('*') == -1:
            result = submit(template_name=template_name, domain=domain, request=request)
            if "result" not in result:
                raise ValueError("incorrect result after certificate submit")

            cer_result = ''.join(result['result'])
            sql = "INSERT INTO certificate(csr, csr_status, email, body, status) " \
                  "VALUES(%s, 'approved', %s, %s, %s) RETURNING id;"
            certificate_id = execute_fetchone(app.db, sql, (csr, body_fields['email'],
                                                            cer_result, 'active',))[0]
        else:
            email = body['email']
            sql = "INSERT INTO certificate(email, csr, csr_status, body, status) VALUES(%s, %s, %s, %s, %s) RETURNING id;"

            certificate_id = execute_fetchone(app.db, sql, (email, csr, 'not approved', '', '',))[0]

            send(body['email'], config.csr('wildcard', 'approve_to_email'),
                      "Please approve wildcard certificate",
                      config.csr('wildcard', 'approve_message') % (certificate_id))

        json_result = certificate_info(app.db, certificate_id)
        return jsonify(json_result)
    except ValueError as ve:
        err_msg = "%s: %s" % (prefix_err_msg, str(ve))
        log.exception(err_msg)
        return jsonify({'error': err_msg}), 500
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400
    except Exception:
        log.exception(prefix_err_msg)
        return jsonify({'error': prefix_err_msg}), 500


@app.route('/certificate/<int:certificate_id>/cer', methods=['GET'])
def certificate_cer(certificate_id):
    prefix_err_msg = "cannot provide certificate"
    try:
        sql = "SELECT * FROM certificate WHERE id=%s"
        certificate_results = query(app.db, sql, (certificate_id,))
        return certificate_results[0]['body'], 200
    except Exception:
        log.exception(prefix_err_msg)
        return jsonify({'error': prefix_err_msg}), 500


@app.route('/certificate/<int:certificate_id>/pem', methods=['GET'])
def certificate_pem(certificate_id):
    def convert(from_, from_data, to):
        CONVERT_STORE_DIR = tempfile.gettempdir()
        OPENSSL_PATH = "openssl"
        if not (from_ == "CER" and to == "PEM"):
            raise ValueError("only input CER and out PEM formats supported")

        from_filepath = os.path.join(CONVERT_STORE_DIR, "in."+from_)
        with open(from_filepath, 'w') as in_file:
            in_file.write(from_data)
            in_file.close()

        to_filepath = os.path.join(CONVERT_STORE_DIR, "out."+to)
        run_args = [OPENSSL_PATH, 'x509', '-in', from_filepath, '-out', to_filepath]
        subprocess.run(run_args)

        result_data = None
        with open(to_filepath, 'r', encoding='utf-8') as to_file:
            result_data = ''.join(to_file.readlines())
            to_file.close()

        return result_data


    prefix_err_msg = "cannot provide certificate"
    try:
        sql = "SELECT * FROM certificate WHERE id=%s"
        certificate_results = query(app.db, sql, (certificate_id,))

        pem_result = convert("CER", certificate_results[0]['body'], "PEM")

        return pem_result, 200
    except Exception:
        log.exception(prefix_err_msg)
        return jsonify({'error': prefix_err_msg}), 500


@app.route('/certificate/<int:certificate_id>/revocation', methods=['POST'])
def certificate_revoke(certificate_id):
    try:
        submit_url = urllib.parse.urljoin(config.windows_service_base_url(), "certificate", "revoke")
        result = requests.post(url=submit_url, json={"domain": "", "request": "", "certificate": certificate_id})
        sql = "UPDATE certificate SET status=%s WHERE id=%s"
        val = ("revoked", certificate_id)
        execute(app.db, sql, val)

        json_result = certificate_info(app.db, certificate_id)
        return json_result
    except Exception:
        err_msg = "cannot update certificate status to revoked"
        log.exception(err_msg)
        return jsonify({'error': err_msg}), 500


@app.route('/certificate/<int:certificate_id>/hold', methods=['POST'])
def certificate_hold(certificate_id):
    def _certificate_hold(id):
        submit_url = urllib.parse.urljoin(config.windows_service_base_url(), "certificate", "hold")
        result = requests.post(url=submit_url, json={"domain": "", "request": "", "certificate": id})
        return result.json()
    try:
        _certificate_hold(certificate_id)

        sql = "UPDATE certificate SET status=%s WHERE id=%s"
        val = ("held", certificate_id)
        execute(app.db, sql, val)

        json_result = certificate_info(app.db, certificate_id)
        return json_result
    except Exception:
        err_msg = "cannot update certificate status to held"
        log.exception(err_msg)
        return jsonify({'error': err_msg}), 500


@app.route('/certificate/<int:certificate_id>/approvecsr', methods=['POST'])
def certificate_approve_csr(certificate_id):
    prefix_err_msg = "cannot approve CSR for certificate"
    try:
        certificate_data = query(app.db, "SELECT * FROM certificate WHERE id=%s", (certificate_id,))
        if len(certificate_data) < 1:
            return RuntimeError('certificate is not found')
        submit_url = urllib.parse.urljoin(config.main('windows_service', 'base_url'), "certificate")
        result = requests.post(url=submit_url, json={"domain": '', "request": certificate_data[0]['csr'], "template": ''})
        result = result.json()
        if "result" not in result:
            raise ValueError("incorrect result after certificate submit")
        cer_result = ''.join(result['result'])
        sql = "UPDATE certificate SET csr_status='approved', body=%s, status='active' WHERE id=%s"
        execute(app.db, sql, (cer_result, certificate_id,))

        certificate_data = query(app.db, "SELECT * FROM certificate WHERE id=%s", (certificate_id,))

        send(config.csr('wildcard', 'approve_from_email'), certificate_data[0]['email'],
                  "Your approve for wildcard certificate #%s" % (certificate_id),
                  config.csr('wildcard', 'approved_message') % (certificate_id))

        json_result = certificate_info(app.db, certificate_id)
        return json_result
    except Exception:
        log.exception(prefix_err_msg)
        return jsonify({'error': prefix_err_msg}), 500


@app.route("/task/cleaning-certificate", methods=['POST'])
def cleaning_certificate():
    prefix_err_msg = "cannot perform certificate cleaning"
    try:
        with app.db.cursor() as cursor:
            sql = "DELETE FROM certificate WHERE created_at<now() - interval '2' day;"
            cursor.execute(sql)

            app.db.commit()

        return jsonify({}, 200)
    except Exception:
        log.exception(prefix_err_msg)
        return jsonify({'error': prefix_err_msg}), 500


@app.route("/task/remembercertificate", methods=['POST'])
def remember_certificate():
    prefix_err_msg = "cannot perform certificate remember"
    try:
        sql = "SELECT * FROM certificate WHERE created_at<now() - interval '60' day;"
        results = query(app.db, sql, ())
        for data in results:
            send(config.csr('wildcard', 'approve_from_email'), data['email'],
                    "Update certificate",
                    "Hello. Please update your certificate with id %s" % (data['id']))
        return jsonify({})
    except Exception:
        log.exception(prefix_err_msg)
        return jsonify({'error': prefix_err_msg}), 500


# utils


def lookup(db, email):
    sql = "SELECT * FROM ldap_user WHERE email=%s"
    users_by_email = query(db, sql, (email,))
    return users_by_email


def search_run(group, ldap_username, ldap_password, attributes=['sAMAccountName']):
    base_dn = 'dc=fpprod,dc=corp'
    args = ['/usr/bin/ldapsearch', '-LLL', '-H', 'ldap://fpprod.corp', '-x', '-D', ldap_username, '-w', ldap_password,
            '-E', 'pr=1000/noprompt', '-b', base_dn, '-s', 'sub', '-x',
            '(&(objectClass=user)(sAMAccountName=*)(memberof=CN='+group+',OU=Groups,OU=Leonteq,DC=fpprod,DC=corp))']
    for a in attributes:
        args.append(a)
    process = subprocess.Popen(args, stdout=subprocess.PIPE)
    (output, err) = process.communicate()
    status = process.wait()
    return output.decode()


def search_output_parse(lines):
    result = [{}]
    for l in lines:
        l = l.rstrip()
        if l == "":
            result.append({})
            continue
        attr_split = l.split(":")
        attr_name, attr_value = attr_split
        attr_value = attr_value.strip()
        #logging.debug('attr_name=%s, attr_value=%s', attr_name, attr_value)

        result[len(result)-1][attr_name] = attr_value

    return [r for r in result if r != {}]


def send(from_, to, subject, message):
    for retry in range(int(config.mail('retry', 'count'))):
        try:
            s = smtplib.SMTP(host=config.mail('smtp', 'host'), port=config.mail('smtp', 'port'))
            user = config.mail('smtp', 'user')
            password = config.mail('smtp', 'password')
            if (user != "") or (password != ""):
                s.starttls()
                s.login(user, password)

            msg = MIMEMultipart()
            msg['From'] = from_
            msg['To'] = to
            msg['Subject'] = subject
            msg.attach(MIMEText(message, 'plain'))
            s.send_message(msg)
            del msg

            s.quit()

            return
        except Exception as e:
            time.sleep(float(config.mail('retry', 'interval')))


def execute(db, sql, params):
    with db.cursor() as cursor:
        cursor.execute(sql, params)
        db.commit()


def execute_fetchone(db, sql, params):
    with db.cursor(cursor_factory=DictCursor) as cursor:
        cursor.execute(sql, params)
        result = cursor.fetchone()
        db.commit()

    return result


def query(db, sql, params):
    with db.cursor(cursor_factory=DictCursor) as cursor:
        cursor.execute(sql, params)
        result = cursor.fetchall()
    return result


def certificate_info(db, certificate_id):
    sql = "SELECT * FROM certificate WHERE id=%s"
    attributes = query(db, sql, (certificate_id,))
    if len(attributes) < 1:
        return {}

    result = {}
    for k, v in attributes[0].items():
        result[k] = v
    return result


# schemas


class CSRCreateSchema(Schema):
    request = fields.String(validate=validate.Length(max=1500), required=True)
    kind = fields.String(validate=validate.OneOf(["wildcard"]), required=True)


class CSRSetStatusSchema(Schema):
    status = fields.String(validate=validate.OneOf(["approved", "not approved"]), required=True)


class CertificateCreateSchema(Schema):
    template = fields.String(required=True)
    request = fields.String(validate=validate.Length(max=1500), required=True)
    email = fields.String(validate=validate.Length(max=255), required=True)
    domain = fields.String(required=False)


# setup 


def setup_app(app):
    if config.has_section('vault'):
        app.vault_client = hvac.Client(config.vault('url'))
        app.vault_client.token = config.vault('token')

        app.keys = app.vault_client.secrets.kv.read_secret_version(path='wsig')['data']['data']
    else:
        app.keys = {'db_username': config.db('username'), 'db_password': config.db('password')}

    app.db = psycopg2.connect("dbname='%s' host='%s' user='%s' password='%s'" %
                              (config.db('name'), config.db('host'),
                               app.keys['db_username'], app.keys['db_password']))


logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
setup_app(app)


