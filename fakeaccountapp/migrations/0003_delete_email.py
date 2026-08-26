from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("fakeaccountapp", "0002_email"),
    ]

    operations = [
        migrations.DeleteModel(
            name="Email",
        ),
    ]