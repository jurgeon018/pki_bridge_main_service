SHELL := /bin/bash
.PHONY: venv tests 

# api endpoints 

curl_listtemplates:
	curl http://127.0.0.1:8000/api/v1/listtemplates/

curl_pingca:
	curl http://127.0.0.1:8000/api/v1/pingca/

curl_trackurl:
	curl \
		-d '{"url": "https://myhost.fpprod.corp:8083/", "contacts": "name.surname@leonteq.com"}' \
		-X POST -H "Content-Type: application/json" \
		http://127.0.0.1:8000/api/v1/trackurl/

curl_listcommands:
	curl http://127.0.0.1:8000/api/v1/listcommands/

curl_get_help:
	curl http://127.0.0.1:8000/api/v1/get_help/listcommands/

curl_submit:
	curl \
	http://127.0.0.1:5002/submit \
	-d '{"secret_key": "windows_service_69018"}' \
	-H 'Content-Type: application/json'

curl_signcert:
	curl \
		-F "requester=andrey.mendela@leonteq.com" \
		-F "template=LeonteqWebSrvManualEnroll" \
		-F "SAN=altname1, altname2, altname3" \
		-F "note=note test example" \
		-F "env=env" \
		-F "certformat=pem" \
		-F "csr=@src/test_data/pki_test.csr" \
		http://127.0.0.1:8000/api/v1/signcert/

curl_addnote:
	curl \
		-d '{"note": "fdsasdf"}' \
		-X POST \
		-H "Content-Type: application/json" \
		http://127.0.0.1:8000/api/v1/addnote/12/


curl_getcert:
	curl http://127.0.0.1:8000/api/v1/getcert/1/?cert_format=json


curl_getcacert:
	curl http://127.0.0.1:8000/api/v1/getcacert/?cert_format=json


curl_getintermediarycert:
	# curl http://127.0.0.1:8000/api/v1/getintermediarycert/?cert_format=text
	curl http://127.0.0.1:8000/api/v1/getintermediarycert/?cert_format=json


curl_getcacertchain:
	curl http://127.0.0.1:8000/api/v1/getcacertchain/?cert_format=text


# management

scan_network:
	python3 src/manage.py scan_network

gen_user:
	# python3 src/manage.py shell -c "from pki_bridge.models import ProjectUser; ProjectUser.objects.create_superuser('admin', 'admin@example.com', 'admin')"
	python3 src/manage.py gen_user

gen_templates:
	python3 src/manage.py gen_templates

gen_commands:
	python3 src/manage.py gen_commands

gen_networks:
	python3 src/manage.py gen_networks

gen_hosts:
	python3 src/manage.py gen_hosts

gen_networks_json:
	python3 src/manage.py gen_networks_json

gen_allowed_cn:
	python3 src/manage.py gen_allowed_cn

gen_settings:
	python3 src/manage.py gen_settings

set_domain_name:
	python3 src/manage.py set_domain_name -d chvirmendev01.fpprod.corp

prep_db:
	make rmdb
	make rmmig
	make mm
	make cpdatamig
	make m
	make r

clear:
	make rmdb
	make rmmig
	make mm
	make m

# django

cpdatamig:
	cp src/pki_bridge/data_migrations.py src/pki_bridge/migrations/0002_data_migrations.py

rmmig:
	find ./src/ -path "*/migrations/*.py" -not -name "__init__.py" -delete
	find ./src/ -path "*/migrations/*.pyc"  -delete

mm:
	python3 ./src/manage.py makemigrations

m:
	python3 ./src/manage.py migrate 

r:
	python3 ./src/manage.py runserver 127.0.0.1:8000

r0:
	python3 ./src/manage.py runserver 0.0.0.0:8000 --insecure

# tests

tests:
	python3 src/manage.py test pki_bridge.tests

tests_functional:
	python3 src/manage.py test pki_bridge.tests.test_functional

test:
	python3 src/manage.py test pki_bridge.tests.$(path)

# docker 

deploy:
	docker-compose build
	docker-compose up -d

down:
	docker-compose down 

# celery

run_celery_worker:
	cd src && celery -A pki_bridge worker -l info

run_celery_beat:
	cd src && celery -A pki_bridge beat -l info

# db 

rmdb:
	make delete_sqlite_db
	# make delete_postgres_db
	# make create_postgres_db

create_postgres_user:
	sudo -u postgres psql -c "create user pki_bridge with password 'pki_bridge69018';"

alter_postgres_user:
	sudo -u postgres psql -c "alter role pki_bridge set client_encoding to 'utf8';"
	sudo -u postgres psql -c "alter role pki_bridge set default_transaction_isolation to 'read committed';"
	sudo -u postgres psql -c "alter role pki_bridge set timezone to 'UTC';"

create_postgres_db:
	sudo -u postgres psql -c "create database pki_bridge owner pki_bridge; "

delete_postgres_db:
	sudo -u postgres psql -c "drop database pki_bridge; "

delete_sqlite_db:
	rm src/db.sqlite3

# utils

csu:
	python3 ./src/manage.py createsuperuser 

create_venv:
	python3 -m venv venv 
	source venv/bin/activate 
	pip3 install -r requirements.txt 

req:
	pip3 install -r requirements.txt 

cp_env:
	cp ./src/.env.example ./src/.env

rmpyc:
	find ./src/ -name '*.pyc' -delete

findpy:
	find ./src/ -name '*.py' | xargs wc -l

findjs:
	find ./src/ -name '*.js' | xargs wc -l

findcsv:
	find ./src/ -name '*.csv' | xargs wc -l




# pytest
run_tests:
	pytest src/pki_bridge/tests -v -s --disable-pytest-warnings
coverage_run:
	coverage run --source src -m pytest src/pki_bridge/tests

coverage_report:
	coverage report -m
