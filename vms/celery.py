from __future__ import absolute_import, unicode_literals
from celery import Celery
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vms.settings')

app = Celery('vms', broker='redis://localhost', include=['cve.tasks','cpe.tasks'])

app.conf.update(
    result_backend='elasticsearch://localhost:9200/celery/results',
    result_expires=86400*2,
    timezone = 'Asia/Kolkata'
)

if __name__ == '__main__':
    app.start()
