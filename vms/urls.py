from django.contrib import admin
from django.urls import path
from django.conf.urls import include
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from . import views
import os
from datetime import datetime

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('django.contrib.auth.urls')),
    path('profile/', views.profile, name='profile'),
    path('accountmanager/', views.accountmanager, name='accountmanager'),
    path('components/', include('cpe.urls', namespace = 'components')),
    path('vulnerabilities/', include('cve.urls', namespace = 'vulnerabilities')),
    path('products/', include('products.urls', namespace = 'products')),
    path('notifications/', include('notifications.urls', namespace = 'notifications')),
    path('', views.home, name='home'),
] + staticfiles_urlpatterns()

APP_ROOT = os.path.abspath(os.path.join(os.path.abspath(__file__),'../..'))

def initial_download():
    if not os.path.exists(os.path.join(APP_ROOT,'cve/cache')):
        os.makedirs(os.path.join(APP_ROOT,'cve/cache'))
        from cve.utils import cve_handler
        obj = cve_handler()
        for year in range(2002,datetime.now().year + 1):
            obj.update_db(str(year))
            print("CVE-"+str(year)+" updated!")

    if not os.path.exists(os.path.join(APP_ROOT,'cpe/cache')):
        makedirs(os.path.join(APP_ROOT,'cpe/cache'))
        from cpe.utils import cpe_handler
        obj = cpe_handler()
        obj.update_db()
        print("CPE db updated!")

initial_download()
