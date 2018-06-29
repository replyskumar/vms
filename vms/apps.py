from django.apps import AppConfig
import os
from datetime import datetime

APP_ROOT = os.path.abspath(os.path.join(os.path.abspath(__file__),'../..'))

class vms_config(AppConfig):
    name = 'vms'
    verbose_name = "Vulnerability Management System"
    def ready(self):
        if os.environ.get('DOWNLOAD','True') == 'True':
            if not os.path.exists(os.path.join(APP_ROOT,'cve/cache')):
                os.makedirs(os.path.join(APP_ROOT,'cve/cache'))
                from cve.utils import cve_handler
                obj = cve_handler()
                for year in range(2002,datetime.now().year + 1):
                    obj.update_db(str(year))
                    print("CVE-"+str(year)+" updated!")

            if not os.path.exists(os.path.join(APP_ROOT,'cpe/cache')):
                os.makedirs(os.path.join(APP_ROOT,'cpe/cache'))
                from cpe.utils import cpe_handler
                obj = cpe_handler()
                obj.update_db()
                print("CPE db updated!")
