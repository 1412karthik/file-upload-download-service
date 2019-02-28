from django.db import models
from django.contrib.auth.models import User


class File(models.Model):
    name = models.CharField(primary_key=True, max_length=200)
    user = models.ForeignKey(User, related_name = 'files', on_delete=models.CASCADE)
    path = models.CharField(max_length=200)

    class Meta:
        ordering = ['name']