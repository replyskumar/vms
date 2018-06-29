from django.urls import path
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from . import views

app_name = "products"

urlpatterns = [
    path('', views.index, name='index'),
    path('add',views.add_product, name='add'),
    path('servers',views.servers, name='servers'),
    path('add_server',views.add_server, name='add_server'),
    path('get_table',views.get_table, name='get_table'),
] + staticfiles_urlpatterns()
