from __future__ import absolute_import, unicode_literals
from celery import Celery
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vms.settings')

app = Celery('vms', broker=os.environ.get('REDIS_URL','redis://localhost'), include=['cve.tasks','cpe.tasks'])

result_backend_url = 'db+' + os.environ.get('DATABASE_URL','mysql://root:toor@localhost:3306/vms')
app.conf.update(
    result_backend=result_backend_url,
    result_expires=86400*2,
    timezone = 'Asia/Kolkata'
)

if __name__ == '__main__':
    app.start()
