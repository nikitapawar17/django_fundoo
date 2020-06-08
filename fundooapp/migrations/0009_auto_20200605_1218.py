# Generated by Django 2.1.7 on 2020-06-05 17:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fundooapp', '0008_auto_20200603_1834'),
    ]

    operations = [
        migrations.RenameField(
            model_name='label',
            old_name='title',
            new_name='label',
        ),
        migrations.AddField(
            model_name='note',
            name='label',
            field=models.ManyToManyField(blank=True, related_name='note_label', to='fundooapp.Label'),
        ),
    ]
