from django.db import models
from django.contrib.auth.models import User
# Create your models here.


# class UserDetail(models.Model):
#     firstname = models.CharField(blank=False, max_length=50)
#     lastname = models.CharField(blank=False, max_length=50)
#     username = models.CharField(max_length=50, blank=False)
#     email = models.EmailField(max_length=255, unique=True)
#     password = models.CharField(max_length=50)
#     is_active = models.BooleanField(default=True)
#
#     def __str__(self):
#         return self.firstname


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
