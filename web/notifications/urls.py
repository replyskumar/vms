from django.urls import path
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from . import views

app_name = "notifications"

urlpatterns = [
    path('', views.index, name='index'),
    path('get/', views.get_notifications, name='get'),
    path('clear/', views.clear_notifications, name='clear'),
] + staticfiles_urlpatterns()
