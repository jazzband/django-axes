from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [("axes", "0004_auto_20181024_1538")]

    operations = [migrations.RemoveField(model_name="accessattempt", name="trusted")]
