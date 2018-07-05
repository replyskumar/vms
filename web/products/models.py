from django.db import models
from django.contrib.auth.models import User


class product(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255,blank=True,unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class server(models.Model):
    id = models.AutoField(primary_key=True)
    product = models.ForeignKey(product, on_delete=models.CASCADE)
    name = models.CharField(max_length=255,blank=True)
    timestamp = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('product', 'name',)

    def __str__(self):
        return self.name
