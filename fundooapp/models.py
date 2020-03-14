from django.db import models
from django.contrib.auth.models import User
# Create your models here.

#
# class User(models.Model):
#     name = models.CharField(max_length=50, blank=False)
#     email = models.EmailField(max_length=255, unique=True)
#     password = models.CharField(max_length=50)
#
#     def __str__(self):
#         return self.name


class Note(models.Model):
    title = models.CharField(max_length=20, blank=False)
    description = models.CharField(max_length=255)
    COLOR_CHOICES = (
        ('Red', 'Red'),
        ('Green', 'Green'),
        ('Blue', 'Blue')
    )
    color = models.CharField(default='Blue', choices=COLOR_CHOICES, max_length=20)
    is_archive = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    is_trash = models.BooleanField(default=False)

    def __str__(self):
        return self.title
