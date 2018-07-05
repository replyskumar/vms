from django.core.management.base import BaseCommand, CommandError
import shutil
import os.path
from datetime import datetime

APP_ROOT = os.path.abspath(os.path.join(os.path.abspath(__file__),'../../../..'))

class Command(BaseCommand):
    help = 'Populate CPE and CVE DBs'


    def handle(self, *args, **options):
        print("Updating... Please wait!")
        shutil.rmtree(os.path.join(APP_ROOT,'cve/cache'))
        if not os.path.exists(os.path.join(APP_ROOT,'cve/cache')):
            os.makedirs(os.path.join(APP_ROOT,'cve/cache'))
        from cve.utils import cve_handler
        obj = cve_handler()
        for year in range(2002,datetime.now().year + 1):
            obj.update_db(str(year))
            print("CVE-"+str(year)+" updated!")

        shutil.rmtree(os.path.join(APP_ROOT,'cpe/cache'),ignore_errors=True)
        if not os.path.exists(os.path.join(APP_ROOT,'cpe/cache')):
            os.makedirs(os.path.join(APP_ROOT,'cpe/cache'))
        from cpe.utils import cpe_handler
        obj = cpe_handler()
        obj.update_db()
        print("CPE db updated!")
