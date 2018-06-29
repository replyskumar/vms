from django.contrib import admin
from django.urls import path
from django.conf.urls import include
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from . import views

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
