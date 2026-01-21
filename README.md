# Backend (Django + DRF)

API del sistema interno (auth JWT, inventario/materiales, usos, ventas, auditoría y administración).

## Requisitos
- Python 3.11+

## Configuración
1) Crear entorno virtual e instalar dependencias:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2) Variables de entorno:

```powershell
Copy-Item .env.example .env
```

Variables principales (ver `.env.example`):
- `DJANGO_SECRET_KEY` (se usa también como secreto JWT)
- `DJANGO_DEBUG` (`1`/`0`)
- `DJANGO_ALLOWED_HOSTS`
- `DJANGO_CORS_ALLOWED_ORIGINS`
- `DATABASE_URL` (Postgres/Supabase)
- `DB_SSL_REQUIRE` (1/0)

## Ejecutar (local)

```powershell
python manage.py migrate
python manage.py seed
python manage.py runserver
```

API base: `http://127.0.0.1:8000/api/`
Admin Django (opcional): `http://127.0.0.1:8000/admin/`

## Datos iniciales (seed)
`python manage.py seed` crea el admin y (si está habilitado) el demo. En producción:
- `SEED_ADMIN_PASSWORD` es obligatorio.
- Usa `SEED_ALLOW_RESET=1` solo si necesitas forzar credenciales.
- `SEED_INCLUDE_DEMO=0` para no crear usuario demo.

## Roles y estados de usuario
- `nivel=0`: administrador.
- Estados: `pendiente | activo | rechazado | baneado`.
- Importante: el backend permite autenticación de `pendiente` (para que pueda entrar a **Mi cuenta**), pero los módulos sensibles deben exigir `estado=activo` vía permisos.

## Endpoints (resumen)
La lista completa está en `api/urls.py`. Algunos puntos clave:

- Salud: `GET /api/health/`
- Auth:
	- `POST /api/auth/login/`
	- `GET /api/auth/me/`
	- Recuperación: `/api/auth/forgot/*`
- Materiales:
	- `GET /api/materiales/`
	- `POST /api/materiales/crear/`
	- `PATCH /api/materiales/<id>/`
	- `DELETE /api/materiales/<id>/eliminar/`
- Usos:
	- `GET /api/materiales/usos/`
	- `POST /api/materiales/usos/crear/`
	- `POST /api/materiales/usos/<id>/devolver/`
- Ventas:
	- `GET /api/materiales/ventas/`
	- `POST /api/materiales/ventas/crear/`
- Historial (movimientos): `GET /api/materiales/movimientos/`

### Exportación CSV
Endpoints:
- `GET /api/materiales/export.csv`
- `GET /api/materiales/usos/export.csv`
- `GET /api/materiales/ventas/export.csv`
- `GET /api/materiales/movimientos/export.csv`

Parámetros comunes:
- `scope=all` para exportar **todo** ignorando filtros (por defecto exporta filtrado).

Filtros avanzados en inventario (`/api/materiales/` y `/api/materiales/export.csv`):
- `logic=and|or`
- `q`, `tipo`, `ubicacion`
- `propio=1|0`, `vendible=1|0`
- Rangos: `cantidad_gte/lte`, `minimo_gte/lte`, `en_uso_gte/lte`
- Orden: `sort=<campo>&order=asc|desc`

## Comandos útiles
- `python manage.py set_user_password <username> <password>`
- `python manage.py mp_set_nivel <username> <nivel>`
- `python manage.py cleanup_audit_logs` (si aplica en tu entorno)
