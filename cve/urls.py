from django.urls import path
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from . import views

app_name = "Vulnerabilities"

urlpatterns = [
    path('', views.index, name='index'),
    path('get', views.get_vuln, name='get'),
    path('update', views.update_vuln, name='update'),
    path('query', views.query_vuln, name='query'),
] + staticfiles_urlpatterns()
