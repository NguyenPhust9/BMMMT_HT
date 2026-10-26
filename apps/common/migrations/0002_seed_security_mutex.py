"""
Data migration to ensure SecurityMutex(id=1) is created automatically on every database migration (Section 6.2, DES-08).
"""
from django.db import migrations


def create_security_mutex_row(apps, schema_editor):
    SecurityMutex = apps.get_model("common", "SecurityMutex")
    SecurityMutex.objects.get_or_create(pk=1)


def remove_security_mutex_row(apps, schema_editor):
    SecurityMutex = apps.get_model("common", "SecurityMutex")
    SecurityMutex.objects.filter(pk=1).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("common", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_security_mutex_row, remove_security_mutex_row),
    ]

