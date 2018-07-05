from django.urls import path
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from . import views

app_name = "components"

urlpatterns = [
    path('', views.index, name='index'),
    path('add',views.add_cpe, name='add'),
    path('get_dropdown',views.get_dropdown, name='get_dropdown'),
    path('get_table',views.get_table, name='get_table'),
    path('get_components',views.get_components, name='get_components'),
    path('get_template',views.get_template, name='get_template'),
    path('get_versions',views.get_versions, name='get_versions'),
    path('save_template',views.save_template, name='save_template'),
    path('save_components',views.save_components, name='save_components'),
    path('add_from_template',views.add_from_template, name='add_from_template'),
    path('autocomplete', views.autocomplete, name='autocomplete'),
] + staticfiles_urlpatterns()
