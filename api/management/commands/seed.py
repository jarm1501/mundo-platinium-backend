import os
import secrets
from datetime import date

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

import bcrypt

from api.models import Material, Usuario
from api.security import hash_answer


def _env(name: str, default: str | None = None) -> str | None:
    val = os.getenv(name)
    if val is None:
        return default
    val = val.strip()
    return val if val else default


def _random_password() -> str:
    # 24 chars URL-safe, suficientemente fuerte para entorno dev.
    return secrets.token_urlsafe(18)


class Command(BaseCommand):
    help = "Crea datos iniciales: admin + usuario demo + materiales demo."

    def add_arguments(self, parser):
        parser.add_argument(
            "--no-materials",
            action="store_true",
            help="No crear materiales demo",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        debug = (_env("DJANGO_DEBUG", "0") == "1")
        allow_reset = (_env("SEED_ALLOW_RESET", "0") == "1")
        include_demo = (_env("SEED_INCLUDE_DEMO", "1") == "1") if debug else (_env("SEED_INCLUDE_DEMO", "0") == "1")

        admin_username = _env("SEED_ADMIN_USERNAME", "admin")
        admin_email = _env("SEED_ADMIN_EMAIL", "admin@local")
        admin_password = _env("SEED_ADMIN_PASSWORD")
        if not debug and not admin_password:
            raise CommandError("SEED_ADMIN_PASSWORD es obligatorio cuando DJANGO_DEBUG=0.")
        if debug and not admin_password:
            admin_password = "admin"

        demo_username = _env("SEED_DEMO_USERNAME", "demo")
        demo_email = _env("SEED_DEMO_EMAIL", "demo@local")
        demo_password = _env("SEED_DEMO_PASSWORD") or ("demo" if debug else None)

        admin_user = Usuario.objects.filter(username__iexact=admin_username).first()
        pw_hash = bcrypt.hashpw(admin_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        if not admin_user:
            admin_user = Usuario.objects.create(
                username=admin_username,
                password_hash=pw_hash,
                nombre="Admin",
                apellido="Root",
                fecha_nacimiento=date(1990, 1, 1),
                email=admin_email,
                telefono="",
                estado="activo",
                nivel=0,
                is_active=True,
                sec_q1="Nombre de tu primera mascota?",
                sec_a1_hash=hash_answer("admin"),
                sec_q2="Ciudad donde naciste?",
                sec_a2_hash=hash_answer("admin"),
            )
            self.stdout.write(self.style.SUCCESS(f"Admin creado: {admin_username} (nivel=0)"))
        else:
            if debug or allow_reset:
                # En dev (o con SEED_ALLOW_RESET), forzar credenciales conocidas.
                admin_user.password_hash = pw_hash
                admin_user.email = admin_email
                admin_user.estado = "activo"
                admin_user.nivel = 0
                admin_user.is_active = True
                admin_user.save(update_fields=["password_hash", "email", "estado", "nivel", "is_active"])
                self.stdout.write(self.style.WARNING(f"Admin actualizado: {admin_username} (nivel=0)"))
            else:
                self.stdout.write(self.style.WARNING(f"Admin existente: {admin_username} (sin cambios)"))

        if include_demo:
            demo_user = Usuario.objects.filter(username__iexact=demo_username).first()
            if not demo_password:
                demo_password = _random_password()
            pw_hash = bcrypt.hashpw(demo_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            if not demo_user:
                demo_user = Usuario.objects.create(
                    username=demo_username,
                    password_hash=pw_hash,
                    nombre="Usuario",
                    apellido="Demo",
                    fecha_nacimiento=date(2000, 1, 1),
                    email=demo_email,
                    telefono="",
                    estado="activo",
                    nivel=1,
                    is_active=True,
                    sec_q1="Nombre de tu primera mascota?",
                    sec_a1_hash=hash_answer("demo"),
                    sec_q2="Ciudad donde naciste?",
                    sec_a2_hash=hash_answer("demo"),
                )
                self.stdout.write(self.style.SUCCESS(f"Usuario demo creado: {demo_username} (nivel=1)"))
            else:
                if debug or allow_reset:
                    demo_user.password_hash = pw_hash
                    demo_user.email = demo_email
                    demo_user.estado = "activo"
                    demo_user.nivel = 1
                    demo_user.is_active = True
                    demo_user.save(update_fields=["password_hash", "email", "estado", "nivel", "is_active"])
                    self.stdout.write(self.style.WARNING(f"Usuario demo actualizado: {demo_username} (nivel=1)"))
                else:
                    self.stdout.write(self.style.WARNING(f"Usuario demo existente: {demo_username} (sin cambios)"))

        if not options.get("no_materials"):
            defaults = [
                ("Guantes", "EPP", 25000, "Bodega", 25, 10, True),
                ("Taladro", "Herramienta", 250000, "Taller", 5, 2, False),
                ("Cinta métrica", "Herramienta", 12000, "Taller", 20, 5, False),
            ]

            created = 0
            for nombre, tipo, precio, ubicacion, cantidad, minimo, propio in defaults:
                _obj, was_created = Material.objects.get_or_create(
                    nombre=nombre,
                    defaults={
                        "tipo": tipo,
                        "precio": precio,
                        "ubicacion": ubicacion,
                        "cantidad": cantidad,
                        "minimo": minimo,
                        "propio": propio,
                    },
                )
                created += 1 if was_created else 0

            self.stdout.write(self.style.SUCCESS(f"Materiales demo creados: {created}"))

        if debug:
            self.stdout.write("\nCredenciales (DEV):")
            self.stdout.write(self.style.WARNING(f"- Admin {admin_username} password: {admin_password}"))
            if include_demo:
                self.stdout.write(self.style.WARNING(f"- Demo  {demo_username} password: {demo_password}"))

        self.stdout.write("\nTip: define SEED_ADMIN_PASSWORD y SEED_DEMO_PASSWORD en backend/.env. En producción usa SEED_ALLOW_RESET=1 solo si necesitas forzar credenciales.")
