from django.db import models
from django.contrib.auth.models import User
import datetime
from django.utils import timezone
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


class Label(models.Model):
    label = models.CharField(max_length=20, blank=False)
    is_deleted = models.BooleanField(default=False, null=True, blank=True)

    def __str__(self):
        return self.label


class Note(models.Model):
    title = models.CharField(max_length=20, blank=False)
    description = models.CharField(max_length=255, null=True)
    COLOR_CHOICES = (
        ('Red', 'Red'),
        ('Green', 'Green'),
        ('Blue', 'Blue')
    )
    color = models.TextField(null=True, blank=True)
    # color = models.CharField(default='Blue', choices=COLOR_CHOICES, max_length=20, null=True)
    label = models.ManyToManyField(Label, related_name='note_label', blank=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    remainder = models.DateTimeField(default=None, null=True)
    is_archive = models.BooleanField(default=False, null=True, blank=True)
    is_deleted = models.BooleanField(default=False, null=True, blank=True)
    is_trash = models.BooleanField(default=False, null=True, blank=True)
    is_pin = models.BooleanField(default=False, null=True, blank=True)
    created_by = models.ForeignKey(User, related_name='note_created_by', on_delete=models.CASCADE, default=1)
    collaborate = models.ManyToManyField(User, related_name='notes', blank=True)

    def __str__(self):
        return self.title
