from django.core.management.base import BaseCommand, CommandError

from api.models import Usuario


class Command(BaseCommand):
    help = "Setea el nivel/estado de un usuario (0=admin, 1=usuario)."

    def add_arguments(self, parser):
        parser.add_argument("username", type=str)
        parser.add_argument("nivel", type=int)
        parser.add_argument("--estado", type=str, default=None)
        parser.add_argument("--active", type=str, default=None, help="true/false para is_active")

    def handle(self, *args, **options):
        username = (options.get("username") or "").strip()
        if not username:
            raise CommandError("username requerido")

        nivel = int(options.get("nivel"))
        if nivel not in (0, 1):
            raise CommandError("nivel debe ser 0 o 1")

        u = Usuario.objects.filter(username__iexact=username).first()
        if not u:
            raise CommandError(f"No existe: {username}")

        update_fields = []
        if u.nivel != nivel:
            u.nivel = nivel
            update_fields.append("nivel")

        estado = options.get("estado")
        if estado is not None:
            estado = (estado or "").strip()
            if estado not in ("pendiente", "activo", "rechazado", "baneado"):
                raise CommandError("estado inválido")
            if u.estado != estado:
                u.estado = estado
                update_fields.append("estado")

        active = options.get("active")
        if active is not None:
            active_val = str(active).strip().lower() in ("1", "true", "yes", "si")
            if u.is_active != active_val:
                u.is_active = active_val
                update_fields.append("is_active")

        if update_fields:
            u.save(update_fields=update_fields)

        self.stdout.write(self.style.SUCCESS(f"OK: {u.username} nivel={u.nivel} estado={u.estado} is_active={u.is_active}"))
