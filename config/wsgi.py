import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

# En Render, ejecutar migraciones automáticamente si está habilitado
if os.getenv("AUTO_MIGRATE", "").lower() in ("1", "true", "yes") or os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"):
	try:
		from django.core.management import call_command
		call_command("migrate", interactive=False)
	except Exception:
		# Si falla, el error aparecerá en logs
		pass

application = get_wsgi_application()
