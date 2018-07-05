from django.db import models
from django.contrib.auth.models import User


class notification(models.Model):

    id = models.AutoField(primary_key=True)
    header = models.CharField(max_length=50)
    message = models.CharField(max_length=300)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    time = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField()

    def __str__(self):
        return self.header
