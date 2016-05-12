# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('axes', '0002_auto_20151217_2044'),
    ]

    operations = [
        migrations.AlterField(
            model_name='accessattempt',
            name='failures_since_start',
            field=models.PositiveIntegerField(verbose_name='Failed Logins'),
        ),
        migrations.AlterField(
            model_name='accessattempt',
            name='get_data',
            field=models.TextField(verbose_name='GET Data'),
        ),
        migrations.AlterField(
            model_name='accessattempt',
            name='http_accept',
            field=models.CharField(verbose_name='HTTP Accept', max_length=1025),
        ),
        migrations.AlterField(
            model_name='accessattempt',
            name='ip_address',
            field=models.GenericIPAddressField(null=True, verbose_name='IP Address', db_index=True),
        ),
        migrations.AlterField(
            model_name='accessattempt',
            name='path_info',
            field=models.CharField(verbose_name='Path', max_length=255),
        ),
        migrations.AlterField(
            model_name='accessattempt',
            name='post_data',
            field=models.TextField(verbose_name='POST Data'),
        ),
        migrations.AlterField(
            model_name='accesslog',
            name='http_accept',
            field=models.CharField(verbose_name='HTTP Accept', max_length=1025),
        ),
        migrations.AlterField(
            model_name='accesslog',
            name='ip_address',
            field=models.GenericIPAddressField(null=True, verbose_name='IP Address', db_index=True),
        ),
        migrations.AlterField(
            model_name='accesslog',
            name='path_info',
            field=models.CharField(verbose_name='Path', max_length=255),
        ),
    ]
