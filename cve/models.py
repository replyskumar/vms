from django.db import models
from cpe.models import component_to_server
from products.models import server

class vulnerability(models.Model):

    id = models.AutoField(primary_key=True)
    cve_id = models.CharField(max_length=16)
    summary = models.TextField()
    published = models.DateTimeField()
    last_modified = models.DateTimeField()
    score_v3 = models.DecimalField(max_digits=3,decimal_places=1)
    score_v2 = models.DecimalField(max_digits=3,decimal_places=1)
    vector_string_v2 = models.CharField(max_length=100)
    vector_string_v3 = models.CharField(max_length=100)
    in_date = models.DateTimeField(auto_now_add=True)
    timestamp = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.cve_id

class affects(models.Model):
    id = models.AutoField(primary_key=True)
    cve = models.ForeignKey(vulnerability, on_delete=models.CASCADE)
    c2s = models.ForeignKey(component_to_server, on_delete=models.CASCADE)
    server = models.ForeignKey(server, on_delete=models.CASCADE)
    custom_score = models.DecimalField(max_digits=3,decimal_places=1)
    comments = models.TextField()
    timestamp = models.DateTimeField(auto_now=True)
