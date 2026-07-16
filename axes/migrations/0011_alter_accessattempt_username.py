from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("axes", "0010_accessattemptexpiration"),
    ]

    operations = [
        migrations.AlterField(
            model_name="accessattempt",
            name="username",
            field=models.CharField(max_length=255, null=True, verbose_name="Username"),
        ),
    ]
