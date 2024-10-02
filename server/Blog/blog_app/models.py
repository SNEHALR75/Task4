from django.db import models

# Create your models here.

class Blog(models.Model):
    title = models.CharField(max_length=50)
    description = models.TextField()
    created_by = models.CharField(max_length=50)
    updated_at = models.DateTimeField(auto_now_add=True)
    