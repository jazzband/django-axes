from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("axes", "0003_auto_20160322_0929")]

    operations = [
        migrations.AlterModelOptions(
            name="accessattempt",
            options={
                "verbose_name": "access attempt",
                "verbose_name_plural": "access attempts",
            },
        ),
        migrations.AlterModelOptions(
            name="accesslog",
            options={
                "verbose_name": "access log",
                "verbose_name_plural": "access logs",
            },
        ),
        migrations.AlterField(
            model_name="accessattempt",
            name="attempt_time",
            field=models.DateTimeField(auto_now_add=True, verbose_name="Attempt Time"),
        ),
        migrations.AlterField(
            model_name="accessattempt",
            name="user_agent",
            field=models.CharField(
                db_index=True, max_length=255, verbose_name="User Agent"
            ),
        ),
        migrations.AlterField(
            model_name="accessattempt",
            name="username",
            field=models.CharField(
                db_index=True, max_length=255, null=True, verbose_name="Username"
            ),
        ),
        migrations.AlterField(
            model_name="accesslog",
            name="attempt_time",
            field=models.DateTimeField(auto_now_add=True, verbose_name="Attempt Time"),
        ),
        migrations.AlterField(
            model_name="accesslog",
            name="logout_time",
            field=models.DateTimeField(
                blank=True, null=True, verbose_name="Logout Time"
            ),
        ),
        migrations.AlterField(
            model_name="accesslog",
            name="user_agent",
            field=models.CharField(
                db_index=True, max_length=255, verbose_name="User Agent"
            ),
        ),
        migrations.AlterField(
            model_name="accesslog",
            name="username",
            field=models.CharField(
                db_index=True, max_length=255, null=True, verbose_name="Username"
            ),
        ),
    ]
