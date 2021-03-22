from celery import shared_task
from celery.task import periodic_task
from datetime import datetime, timedelta
from pki_bridge.core.scanner import scan_network


@periodic_task(run_every=timedelta(minutes=1))
def celery_scan_network_periodically():
    celery_scan_network.delay()


@shared_task
def celery_scan_network():
    scan_network()


# from celery.schedules import crontab
# from celery.task.schedules import crontab
# @periodic_task(run_every=crontab(hour=0, minute=0, day_of_week="mon"))
# @periodic_task(run_every=crontab(hour=0, minute=0))
@periodic_task(run_every=timedelta(seconds=10))
def celery_test_every_10_seconds():
    print(f'celery_test_every_10_seconds started in {datetime.now()}')
    celery_test.delay()
    return f'celery_test_every_10_seconds finished in {datetime.now()}'


@shared_task
def celery_test():
    print(f'celery_test started in {datetime.now()}')
    return f'celery_test finished in {datetime.now()}'
