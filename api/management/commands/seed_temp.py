import os
from datetime import date
from django.core.management.base import BaseCommand
from django.db import transaction
import bcrypt
from api.models import Material, Usuario
from api.security import hash_answer

# Este seed es TEMPORAL. Úsalo solo para poblar la base con los datos actuales y elimínalo después.
# Puedes modificar los datos aquí para que reflejen el estado real de tu base de datos.

class Command(BaseCommand):
    help = "Seed temporal: pobla la base con los datos actuales (usuarios, materiales, etc). Elimina este archivo después de migrar."

    @transaction.atomic
    def handle(self, *args, **options):
        # Usuarios (copiados de app_db_dump.txt)
        usuarios = [
            # username, password, nombre, apellido, fecha_nacimiento, email, telefono, estado, nivel, is_active
            ("chuandro", "1234", "Jesús Alejandro", "Rodriguez Morales", date(2005, 1, 15), "jesusarodriguezm2005@gmail.com", "04128312628", "activo", 0, True),
            ("demo", "demo", "Usuario", "Demo", date(2000, 1, 1), "demo@local", "", "pendiente", 1, True),
            ("u_demo_01", "demo01", "Nombre1", "Apellido1", date(1995, 1, 1), "u_demo_01@demo.local", "555-01001", "pendiente", 1, True),
            ("u_demo_02", "demo02", "Nombre2", "Apellido2", date(1995, 1, 2), "u_demo_02@demo.local", "555-01002", "pendiente", 1, True),
            ("u_demo_03", "demo03", "Nombre3", "Apellido3", date(1995, 1, 3), "u_demo_03@demo.local", "555-01003", "rechazado", 1, True),
            ("u_demo_04", "demo04", "Nombre4", "Apellido4", date(1995, 1, 4), "u_demo_04@demo.local", "555-01004", "rechazado", 1, True),
            ("user", "user", "Nombre5", "Apellido5", date(1995, 1, 5), "u_demo_05@demo.local", "555-01005", "pendiente", 1, True),
            ("usuario", "usuario", "Nombre6", "Apellido6", date(1995, 1, 6), "u_demo_06@demo.local", "555-01006", "activo", 1, True),
            ("u_demo_07", "demo07", "Nombre7", "Apellido7", date(1995, 1, 7), "u_demo_07@demo.local", "555-01007", "activo", 1, True),
            ("u_demo_08", "demo08", "Nombre8", "Apellido8", date(1995, 1, 8), "u_demo_08@demo.local", "555-01008", "activo", 1, True),
            ("u_demo_09", "demo09", "Nombre9", "Apellido9", date(1995, 1, 9), "u_demo_09@demo.local", "555-01009", "activo", 1, True),
            ("u_demo_10", "demo10", "Nombre10", "Apellido10", date(1995, 1, 10), "u_demo_10@demo.local", "555-01010", "activo", 1, True),
            ("admin_demo_01", "admin01", "Nombre11", "Apellido11", date(1995, 1, 11), "admin_demo_01@demo.local", "555-01011", "activo", 1, True),
            ("admin_demo_02", "admin02", "Nombre12", "Apellido12", date(1995, 1, 12), "admin_demo_02@demo.local", "555-01012", "activo", 0, True),
            ("mam", "mam", "dfvdfdf", "dfvdff", date(2024, 6, 21), "mamitas@gmaill.com", None, "activo", 1, True),
        ]
        for u in usuarios:
            username, password, nombre, apellido, fecha_nacimiento, email, telefono, estado, nivel, is_active = u
            pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            obj, created = Usuario.objects.update_or_create(
                username=username,
                defaults={
                    "password_hash": pw_hash,
                    "nombre": nombre,
                    "apellido": apellido,
                    "fecha_nacimiento": fecha_nacimiento,
                    "email": email,
                    "telefono": telefono or "",
                    "estado": estado,
                    "nivel": nivel,
                    "is_active": is_active,
                    "sec_q1": "Pregunta 1",
                    "sec_a1_hash": hash_answer(password),
                    "sec_q2": "Pregunta 2",
                    "sec_a2_hash": hash_answer(password),
                },
            )
            self.stdout.write(self.style.SUCCESS(f"Usuario {'creado' if created else 'actualizado'}: {username}"))

        # Materiales (copiados de app_db_dump.txt)
        materiales = [
            # nombre, tipo, precio, ubicacion, cantidad, minimo, propio, unidad, precio_venta, vendible
            ("Guantes", "EPP", 25000, "Bodega", 25, 10, True, "unidad", 0, False),
            ("Taladro", "Herramienta", 250000, "Taller", 5, 2, False, "unidad", 0, False),
            ("Cinta métrica", "Herramienta", 12000, "Taller", 20, 5, False, "unidad", 0, False),
            ("Aceite (comestible)", "Comida", 1, "Almacen", 10, 0, True, "unidad", 3, True),
        ]
        for m in materiales:
            nombre, tipo, precio, ubicacion, cantidad, minimo, propio, unidad, precio_venta, vendible = m
            obj, created = Material.objects.update_or_create(
                nombre=nombre,
                defaults={
                    "tipo": tipo,
                    "precio": precio,
                    "ubicacion": ubicacion,
                    "cantidad": cantidad,
                    "minimo": minimo,
                    "propio": propio,
                    "unidad": unidad,
                    "precio_venta": precio_venta,
                    "vendible": vendible,
                },
            )
            self.stdout.write(self.style.SUCCESS(f"Material {'creado' if created else 'actualizado'}: {nombre}"))

        self.stdout.write(self.style.WARNING("\nEste seed es TEMPORAL. Elimínalo después de migrar los datos correctamente."))
