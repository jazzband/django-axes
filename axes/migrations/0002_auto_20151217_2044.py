from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("axes", "0001_initial")]

    operations = [
        migrations.AlterField(
            model_name="accessattempt",
            name="ip_address",
            field=models.GenericIPAddressField(
                db_index=True, null=True, verbose_name="IP Address"
            ),
        ),
        migrations.AlterField(
            model_name="accessattempt",
            name="trusted",
            field=models.BooleanField(db_index=True, default=False),
        ),
        migrations.AlterField(
            model_name="accessattempt",
            name="user_agent",
            field=models.CharField(db_index=True, max_length=255),
        ),
        migrations.AlterField(
            model_name="accessattempt",
            name="username",
            field=models.CharField(db_index=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name="accesslog",
            name="ip_address",
            field=models.GenericIPAddressField(
                db_index=True, null=True, verbose_name="IP Address"
            ),
        ),
        migrations.AlterField(
            model_name="accesslog",
            name="trusted",
            field=models.BooleanField(db_index=True, default=False),
        ),
        migrations.AlterField(
            model_name="accesslog",
            name="user_agent",
            field=models.CharField(db_index=True, max_length=255),
        ),
        migrations.AlterField(
            model_name="accesslog",
            name="username",
            field=models.CharField(db_index=True, max_length=255, null=True),
        ),
    ]
