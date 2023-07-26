from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = []

    operations = [
        migrations.CreateModel(
            name="AccessAttempt",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                ("user_agent", models.CharField(max_length=255)),
                (
                    "ip_address",
                    models.GenericIPAddressField(null=True, verbose_name="IP Address"),
                ),
                ("username", models.CharField(max_length=255, null=True)),
                ("trusted", models.BooleanField(default=False)),
                (
                    "http_accept",
                    models.CharField(max_length=1025, verbose_name="HTTP Accept"),
                ),
                ("path_info", models.CharField(max_length=255, verbose_name="Path")),
                ("attempt_time", models.DateTimeField(auto_now_add=True)),
                ("get_data", models.TextField(verbose_name="GET Data")),
                ("post_data", models.TextField(verbose_name="POST Data")),
                (
                    "failures_since_start",
                    models.PositiveIntegerField(verbose_name="Failed Logins"),
                ),
            ],
            options={"ordering": ["-attempt_time"], "abstract": False},
        ),
        migrations.CreateModel(
            name="AccessLog",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                ("user_agent", models.CharField(max_length=255)),
                (
                    "ip_address",
                    models.GenericIPAddressField(null=True, verbose_name="IP Address"),
                ),
                ("username", models.CharField(max_length=255, null=True)),
                ("trusted", models.BooleanField(default=False)),
                (
                    "http_accept",
                    models.CharField(max_length=1025, verbose_name="HTTP Accept"),
                ),
                ("path_info", models.CharField(max_length=255, verbose_name="Path")),
                ("attempt_time", models.DateTimeField(auto_now_add=True)),
                ("logout_time", models.DateTimeField(null=True, blank=True)),
            ],
            options={"ordering": ["-attempt_time"], "abstract": False},
        ),
    ]
