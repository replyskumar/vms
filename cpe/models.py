from django.db import models
from products.models import server
from django.db.models.signals import post_save
from django.dispatch import receiver

class component(models.Model):

    id = models.AutoField(primary_key=True)
    cpe_id = models.CharField(max_length=255,blank=True)
    title = models.TextField(blank=True)
    wfs = models.CharField(max_length=255,blank=True)
    timestamp = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.cpe_id

class component_to_server(models.Model):
    id = models.AutoField(primary_key=True)
    server = models.ForeignKey(server, on_delete=models.CASCADE)
    cpe = models.ForeignKey(component, on_delete=models.CASCADE)
