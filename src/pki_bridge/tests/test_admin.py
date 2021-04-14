# сделать админку красивой и многофункциональной
# scan autocomplete field on device
# rangefilters on datetime
# filter certificates(cert_exp, dates, days_left range etc)
# filter scans(cert_exp, dates, days_left range error_msg, etc)
# custom filter "without network" on host
# заблокировать CRUD действия во всех нужных местах
# scan_network button
# scan_hosts button
# scan_certificates button
# CertificateRequestAdmin.readonly_fields put link to certificate page
# HostScanAdmin.list_filter link to certificate page
# HostScanAdmin.list_filter autocomplete
# scan_db_certificates  filter certificates which hasnt been scanned yet

# # # models fields:
# show as text in admin
# show valid_days_to_expire fields in admin
# show validity_days fields in admin
# show is_expired fields in admin
# show text_cert in admin
# show json_cert in admin


import pytest


# TODO test admin
class TestAdmin:
    pass
