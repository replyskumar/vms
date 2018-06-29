from __future__ import absolute_import, unicode_literals
from celery import Celery
import os
from vms.settings import USE_ELASTIC_SEARCH

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vms.settings')

app = Celery('vms', broker=os.environ.get('REDIS_URL','redis://localhost'), include=['cve.tasks','cpe.tasks'])

app.conf.update(
    result_backend='django-db',
    result_expires=86400*2,
    timezone = 'Asia/Kolkata'
)

if __name__ == '__main__':
    app.start()
