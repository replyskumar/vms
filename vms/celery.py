from __future__ import absolute_import, unicode_literals
from celery import Celery
import os
from vms.settings import USE_ELASTIC_SEARCH,ELASTIC_SEARCH_URL

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vms.settings')

app = Celery('vms', broker=os.environ.get('REDIS_URL','redis://localhost'), include=['cve.tasks','cpe.tasks'])

if 1==2:
    result_backend_url = os.environ.get('ELASTICSEARCH_URL','http://localhost:9200').replace('http://','elasticsearch://').replace('https://','elasticsearch://')+'/celery/results'
else:
    result_backend_url = 'db+' + os.environ.get('DATABASE_URL','mysql://root:toor@localhost:3306/vms')
app.conf.update(
    result_backend=result_backend_url,
    result_expires=86400*2,
    timezone = 'Asia/Kolkata'
)

if __name__ == '__main__':
    app.start()
