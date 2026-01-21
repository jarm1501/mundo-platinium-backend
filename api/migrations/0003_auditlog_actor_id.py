from django.db import migrations, models


def backfill_actor_id(apps, schema_editor):
    AuditLog = apps.get_model("api", "AuditLog")
    Usuario = apps.get_model("api", "Usuario")

    # Recolecta actores distintos (ignorando system/vacíos)
    actors = (
        AuditLog.objects.exclude(actor__isnull=True)
        .exclude(actor="")
        .exclude(actor__iexact="system")
        .filter(actor_id__isnull=True)
        .values_list("actor", flat=True)
        .distinct()
    )
    actors = list(actors)
    if not actors:
        return

    user_map = {u.username: u.id for u in Usuario.objects.filter(username__in=actors).only("id", "username")}
    if not user_map:
        return

    # Actualiza en batches para evitar queries enormes
    batch = []
    for log in AuditLog.objects.filter(actor_id__isnull=True).exclude(actor__iexact="system").exclude(actor=""):
        aid = user_map.get(log.actor)
        if aid is None:
            continue
        log.actor_id = aid
        batch.append(log)
        if len(batch) >= 500:
            AuditLog.objects.bulk_update(batch, ["actor_id"])
            batch = []

    if batch:
        AuditLog.objects.bulk_update(batch, ["actor_id"])


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0002_usuario_refactor"),
    ]

    operations = [
        migrations.AddField(
            model_name="auditlog",
            name="actor_id",
            field=models.BigIntegerField(blank=True, null=True),
        ),
        migrations.RunPython(backfill_actor_id, migrations.RunPython.noop),
    ]
