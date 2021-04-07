from celery import shared_task
from celery.task import periodic_task
from datetime import datetime, timedelta
from pki_bridge.core.scanner import Scanner


@periodic_task(run_every=timedelta(minutes=1))
def celery_scan_network_periodically():
    print(f'celery_scan_network_periodically started in {datetime.now()}')
    celery_scan_network.delay()
    return f'celery_scan_network_periodically started in {datetime.now()}'


@shared_task(bind=True)
def celery_scan_network(self):
    # print(self)
    Scanner().scan_network()


@shared_task(bind=True)
def celery_scan_db_certificates(self):
    Scanner().scan_db_certificates()


@shared_task(bind=True)    
def celery_scan_hosts(self):
    Scanner().scan_hosts()


# from celery.schedules import crontab
# from celery.task.schedules import crontab
# @periodic_task(run_every=crontab(hour=0, minute=0, day_of_week="mon"))
# @periodic_task(run_every=crontab(hour=0, minute=0))
@periodic_task(run_every=timedelta(seconds=10))
def celery_test_every_10_seconds():
    print(f'celery_test_every_10_seconds started in {datetime.now()}')
    celery_test.delay()
    return f'celery_test_every_10_seconds finished in {datetime.now()}'


@shared_task(bind=True)
def celery_test(self):
    print(f'celery_test started in {datetime.now()}')
    return f'celery_test finished in {datetime.now()}'
