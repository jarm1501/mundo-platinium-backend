from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Usuario",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("username", models.CharField(max_length=80, unique=True)),
                ("password_hash", models.CharField(max_length=200)),
                ("cedula", models.CharField(max_length=20, unique=True)),
                ("nombre", models.CharField(max_length=120)),
                ("apellido", models.CharField(max_length=120)),
                ("fecha_nacimiento", models.DateField()),
                ("email", models.EmailField(blank=True, max_length=254, null=True)),
                ("telefono", models.CharField(blank=True, max_length=30, null=True)),
                ("cedula_change_count", models.PositiveSmallIntegerField(default=0)),
                ("fecha_nacimiento_change_count", models.PositiveSmallIntegerField(default=0)),
                (
                    "estado",
                    models.CharField(
                        choices=[
                            ("pendiente", "pendiente"),
                            ("activo", "activo"),
                            ("rechazado", "rechazado"),
                            ("baneado", "baneado"),
                        ],
                        default="pendiente",
                        max_length=20,
                    ),
                ),
                ("nivel", models.IntegerField(default=1)),
                ("is_active", models.BooleanField(default=True)),
                ("sec_q1", models.CharField(max_length=200)),
                ("sec_a1_hash", models.CharField(max_length=200)),
                ("sec_q2", models.CharField(max_length=200)),
                ("sec_a2_hash", models.CharField(max_length=200)),
                ("signup_ip_hash", models.CharField(blank=True, max_length=64, null=True)),
                ("signup_ip_enc", models.TextField(blank=True, null=True)),
                ("last_login_ip_hash", models.CharField(blank=True, max_length=64, null=True)),
                ("last_login_ip_enc", models.TextField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.DeleteModel(
            name="Profile",
        ),
    ]
