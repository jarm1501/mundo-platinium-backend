import bcrypt
from django.core.management.base import BaseCommand

from api.models import Usuario


class Command(BaseCommand):
    help = "Setea la contraseña (bcrypt) de un Usuario por username. Útil si perdiste la clave en dev."

    def add_arguments(self, parser):
        parser.add_argument("username", type=str)
        parser.add_argument("password", type=str)

    def handle(self, *args, **options):
        username = (options.get("username") or "").strip()
        password = options.get("password") or ""

        if not username or not password:
            self.stderr.write("Uso: python manage.py set_user_password <username> <password>")
            return

        u = Usuario.objects.filter(username__iexact=username).first()
        if not u:
            self.stderr.write(f"Usuario no existe: {username}")
            return

        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        u.password_hash = pw_hash
        u.save(update_fields=["password_hash"])

        self.stdout.write(self.style.SUCCESS(f"OK: password actualizado para {u.username}"))
