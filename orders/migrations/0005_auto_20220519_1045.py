# Generated by Django 3.1 on 2022-05-19 10:45

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('orders', '0004_auto_20220518_1601'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='orderproduct',
            name='color',
        ),
        migrations.RemoveField(
            model_name='orderproduct',
            name='size',
        ),
    ]
