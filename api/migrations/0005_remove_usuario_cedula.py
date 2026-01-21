from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0004_auditlog_actor_id_backfill_ci"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="usuario",
            name="cedula",
        ),
        migrations.RemoveField(
            model_name="usuario",
            name="cedula_change_count",
        ),
    ]
