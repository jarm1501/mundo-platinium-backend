from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0007_material_precio_venta_material_vendible_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="usuario",
            name="session_token",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
    ]
