from django.apps import AppConfig
from os import path,makedirs
from datetime import datetime
from vms.settings import TESTING

APP_ROOT = path.abspath(path.join(path.abspath(__file__),'../..'))

class vms_config(AppConfig):
    name = 'vms'
    verbose_name = "Vulnerability Management System"
    def ready(self):
        if not TESTING:
            if not path.exists(path.join(APP_ROOT,'cve/cache')):
                makedirs(path.join(APP_ROOT,'cve/cache'))
                from cve.utils import cve_handler
                obj = cve_handler()
                for year in range(2002,datetime.now().year + 1):
                    obj.update_db(str(year))
                    print("CVE-"+str(year)+" updated!")

            if not path.exists(path.join(APP_ROOT,'cpe/cache')):
                makedirs(path.join(APP_ROOT,'cpe/cache'))
                from cpe.utils import cpe_handler
                obj = cpe_handler()
                obj.update_db()
                print("CPE db updated!")
