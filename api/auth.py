import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed


def _secret() -> str:
    # Mantener compat con el .env actual de proyec2
    return os.environ.get("MP_SECRET_KEY") or os.environ.get("DJANGO_SECRET_KEY") or "dev-only-change-me"


def make_token(username: str, nivel: int, uid: int, limited: bool = False, sid: str | None = None):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "uid": int(uid),
        "nivel": int(nivel),
        "limited": bool(limited),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=8)).timestamp()),
    }
    if sid:
        payload["sid"] = sid
    return jwt.encode(payload, _secret(), algorithm="HS256")


@dataclass
class MPUser:
    id: int
    username: str
    nivel: int
    estado: str = "activo"
    limited: bool = False
    is_authenticated: bool = True


class MPJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth = request.headers.get("Authorization") or ""
        if not auth:
            return None

        parts = auth.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise AuthenticationFailed("Authorization inválida")

        token = parts[1].strip()
        try:
            payload = jwt.decode(token, _secret(), algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token expirado")
        except Exception:
            raise AuthenticationFailed("Token inválido")

        try:
            uid = int(payload.get("uid"))
            username = str(payload.get("sub"))
            limited = bool(payload.get("limited", False))
        except Exception:
            raise AuthenticationFailed("Token inválido")

        # `nivel` se deriva desde BD para:
        # - compatibilidad con tokens antiguos sin claim `nivel`
        # - reflejar cambios de rol inmediatamente
        nivel = 1

        # Validación contra BD:
        # - Si el usuario fue desactivado, el token deja de servir inmediatamente.
        # - Permitimos estado "pendiente" para que pueda entrar solo a "Mi cuenta".
        #   El resto de endpoints deben protegerse con permisos adicionales (p. ej. estado=="activo").
        try:
            from .models import Usuario

            dbu = Usuario.objects.filter(id=uid).values_list("is_active", "estado", "nivel", "session_token").first()
            if not dbu:
                raise AuthenticationFailed("Usuario no existe")
            is_active, estado, db_nivel, session_token = dbu
            if not is_active:
                raise AuthenticationFailed("Cuenta inactiva")
            if estado not in ("activo", "pendiente"):
                raise AuthenticationFailed("Cuenta no aprobada")
            if session_token:
                token_sid = str(payload.get("sid") or "")
                if not token_sid or token_sid != str(session_token):
                    raise AuthenticationFailed("Sesión inválida")
            try:
                nivel = int(db_nivel)
            except Exception:
                nivel = 1
        except AuthenticationFailed:
            raise
        except Exception:
            # Si hay error de BD, fallamos cerrado.
            raise AuthenticationFailed("No se pudo validar el usuario")

        user = MPUser(id=uid, username=username, nivel=nivel, estado=str(estado or ""), limited=limited)
        return (user, None)
