from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from api.models import AuditLog


class Command(BaseCommand):
    help = "Elimina auditorías antiguas (por defecto: > 365 días)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=365,
            help="Retención en días. Se borran logs con ts < now - days (default: 365).",
        )

    def handle(self, *args, **options):
        days = int(options.get("days") or 365)
        if days < 1:
            self.stderr.write("--days debe ser >= 1")
            return

        cutoff = timezone.now() - timedelta(days=days)
        qs = AuditLog.objects.filter(ts__lt=cutoff)
        count = qs.count()
        qs.delete()

        self.stdout.write(f"AuditLog: eliminados {count} registros anteriores a {cutoff.isoformat()}")
