curl -F "requester=andrey.mendela@leonteq.com" -F "template=LeonteqWebSrvManualEnroll" -F "SAN=['altname1', 'altname2', 'altname3', ]" -F "note=note" -F "env=env" -F "certformat=certformat" -F "csr=@src/test_data/pki_test.csr" http://127.0.0.1:8000/api/v1/signcert/


