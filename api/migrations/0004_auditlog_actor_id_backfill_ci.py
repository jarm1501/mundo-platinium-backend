from django.db import migrations


def backfill_actor_id_case_insensitive(apps, schema_editor):
    AuditLog = apps.get_model("api", "AuditLog")
    Usuario = apps.get_model("api", "Usuario")

    username_to_id = {}
    for user_id, username in Usuario.objects.values_list("id", "username"):
        if username:
            username_to_id[username.lower()] = user_id

    qs = (
        AuditLog.objects.filter(actor_id__isnull=True)
        .exclude(actor__isnull=True)
        .exclude(actor="")
    )

    to_update = []
    for log in qs.iterator(chunk_size=2000):
        actor_txt = (log.actor or "").strip()
        if not actor_txt or actor_txt.lower() == "system":
            continue

        actor_id = username_to_id.get(actor_txt.lower())
        if actor_id is None:
            continue

        log.actor_id = actor_id
        to_update.append(log)

        if len(to_update) >= 2000:
            AuditLog.objects.bulk_update(to_update, ["actor_id"], batch_size=2000)
            to_update = []

    if to_update:
        AuditLog.objects.bulk_update(to_update, ["actor_id"], batch_size=2000)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0003_auditlog_actor_id"),
    ]

    operations = [
        migrations.RunPython(backfill_actor_id_case_insensitive, migrations.RunPython.noop),
    ]
