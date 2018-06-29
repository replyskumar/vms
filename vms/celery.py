from __future__ import absolute_import, unicode_literals
from celery import Celery
import os
from vms.settings import USE_ELASTIC_SEARCH

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vms.settings')

app = Celery('vms', broker=os.environ.get('REDIS_URL','redis://localhost'), include=['cve.tasks','cpe.tasks'])

if USE_ELASTIC_SEARCH:
    backend_url = os.environ.get('ELASTICSEARCH_URL','https://localhost:9200').replace('https','elasticsearch')+'/celery/results'
else:
    backend_url = 'django-db'

app.conf.update(
    result_backend=backend_url,
    result_expires=86400*2,
    timezone = 'Asia/Kolkata'
)

if __name__ == '__main__':
    app.start()
