import csv
import io
import json
import logging
import secrets
import string
from uuid import uuid4
from decimal import Decimal, InvalidOperation
from datetime import date, datetime, timedelta, timezone as dt_timezone

import bcrypt
import jwt
from django.conf import settings
from django.db import transaction
from django.db.models import F, Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone as dj_timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .auth import make_token
from .models import AuditLog, IpRecord, Material, MaterialMovimiento, MaterialUso, MaterialUsoItem, MaterialVenta, MaterialVentaItem, Usuario
from .permissions import IsAdminNivel0, IsEstadoActivo
from .security import decrypt_ip, encrypt_ip, geo_hint, hash_answer, ip_hash, verify_answer
from .serializers import (
    AdminUsuarioSerializer,
    AdminUsuarioEditSerializer,
    ChangePasswordSerializer,
    DeleteAccountSerializer,
    IpRecordSerializer,
    MaterialSerializer,
    MaterialMovimientoSerializer,
    MaterialUsoSerializer,
    MaterialVentaSerializer,
    MeUsuarioSerializer,
    RegisterRequestSerializer,
    ResetPasswordSerializer,
    UpdateSecurityQASerializer,
    UsuarioAdminSerializer,
)


def _to_dec(v, default=Decimal("0")):
    if v is None:
        return default
    if isinstance(v, Decimal):
        return v
    if isinstance(v, (int, float)):
        try:
            return Decimal(str(v))
        except Exception:
            return default
    s = str(v).strip()
    if not s:
        return default
    # Permitir coma como separador decimal
    s = s.replace(" ", "").replace(",", ".")
    try:
        return Decimal(s)
    except InvalidOperation:
        return default


def _dec_nonneg(v: Decimal):
    try:
        return v if v >= 0 else Decimal("0")
    except Exception:
        return Decimal("0")


def _dec_round(v: Decimal):
    # Mantener 3 decimales consistentes con el modelo
    try:
        return v.quantize(Decimal("0.001"))
    except Exception:
        return Decimal("0")


def _audit(actor: str, action: str, entity: str, entity_id=None, before=None, after=None):
    actor_txt = (actor or "").strip()
    actor_id = None
    if actor_txt and actor_txt.lower() != "system":
        try:
            actor_id = Usuario.objects.filter(username__iexact=actor_txt).values_list("id", flat=True).first()
        except Exception:
            actor_id = None

    AuditLog.objects.create(
        actor=actor_txt,
        actor_id=actor_id,
        action=action,
        entity=entity,
        entity_id=entity_id,
        before_json=json.dumps(before, ensure_ascii=False) if before is not None else None,
        after_json=json.dumps(after, ensure_ascii=False) if after is not None else None,
    )


def _client_ip(request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return (xff.split(",")[0] or "").strip() or "unknown"
    return request.META.get("REMOTE_ADDR") or "unknown"


def _iprec(request) -> IpRecord:
    ip = _client_ip(request)
    h = ip_hash(ip)
    rec = IpRecord.objects.filter(ip_hash=h).first()
    if rec:
        return rec
    gh = geo_hint(ip)
    return IpRecord.objects.create(
        ip_hash=h,
        ip_enc=encrypt_ip(ip),
        estado=IpRecord.Estado.OK,
        geo_country=gh.country,
        geo_region=gh.region,
    )


def _require_admin_password(request):
    admin_password = request.data.get("admin_password") or ""
    if not admin_password:
        return (False, Response({"detail": "admin_password requerida"}, status=status.HTTP_400_BAD_REQUEST))

    admin_id = int(getattr(request.user, "id", 0) or 0)
    admin_user = get_object_or_404(Usuario, pk=admin_id)
    stored = (admin_user.password_hash or "").encode("utf-8")
    try:
        ok = bcrypt.checkpw(admin_password.encode("utf-8"), stored)
    except Exception:
        ok = False
    if not ok:
        return (False, Response({"detail": "Clave de administrador incorrecta."}, status=status.HTTP_403_FORBIDDEN))
    return (True, admin_user)


def _ip_is_blocked(rec: IpRecord):
    now = dj_timezone.now()
    if rec.estado == IpRecord.Estado.BANNED:
        return ("banned", None)
    if rec.estado == IpRecord.Estado.COOLDOWN and rec.cooldown_until and rec.cooldown_until > now:
        return ("cooldown", rec.cooldown_until)
    if rec.estado == IpRecord.Estado.COOLDOWN and rec.cooldown_until and rec.cooldown_until <= now:
        rec.estado = IpRecord.Estado.OK
        rec.cooldown_until = None
        rec.save(update_fields=["estado", "cooldown_until"])
    return (None, None)


def _forgot_fail_policy(rec: IpRecord):
    if rec.forgot_step == 1:
        rec.forgot_fail1 += 1
        if rec.forgot_fail1 >= 3:
            rec.forgot_step = 2
            rec.forgot_fail1 = 0
        rec.save(update_fields=["forgot_step", "forgot_fail1", "last_seen"])
        return

    rec.forgot_fail2 += 1
    if rec.forgot_fail2 < 3:
        rec.save(update_fields=["forgot_fail2", "last_seen"])
        return

    if rec.forgot_round == 0:
        rec.estado = IpRecord.Estado.COOLDOWN
        rec.cooldown_until = dj_timezone.now() + timedelta(hours=2)
        rec.forgot_round = 1
        rec.forgot_step = 1
        rec.forgot_fail1 = 0
        rec.forgot_fail2 = 0
        rec.save(
            update_fields=[
                "estado",
                "cooldown_until",
                "forgot_round",
                "forgot_step",
                "forgot_fail1",
                "forgot_fail2",
                "last_seen",
            ]
        )
        _audit("system", "SECURITY", "forgot_cooldown", None)
        return

    rec.estado = IpRecord.Estado.BANNED
    rec.cooldown_until = None
    rec.save(update_fields=["estado", "cooldown_until", "last_seen"])
    _audit("system", "SECURITY", "forgot_banned", None)


def _make_reset_token(username: str, uid: int):
    now = datetime.now(dt_timezone.utc)
    payload = {
        "sub": username,
        "uid": uid,
        "purpose": "pwreset",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def _decode_reset_token(token: str):
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    if payload.get("purpose") != "pwreset":
        raise ValueError("bad token")
    return payload


@api_view(["GET"])
@permission_classes([AllowAny])
def health(_request):
    return Response({"ok": True})


@api_view(["POST"])
@permission_classes([AllowAny])
def register_request(request):
    rec = _iprec(request)
    blocked, _until = _ip_is_blocked(rec)
    if blocked == "banned":
        return Response({"detail": "Acceso bloqueado. Contacta a un administrador."}, status=status.HTTP_403_FORBIDDEN)
    if blocked == "cooldown":
        return Response({"detail": "Demasiados intentos. Intenta más tarde."}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    ser = RegisterRequestSerializer(data=request.data)
    if not ser.is_valid():
        return Response({"detail": "Datos inválidos"}, status=status.HTTP_400_BAD_REQUEST)

    d = ser.validated_data
    username = d["usuario"].strip()

    if Usuario.objects.filter(username__iexact=username).exists():
        return Response({"detail": "usuario ya existe"}, status=status.HTTP_400_BAD_REQUEST)

    pw_hash = bcrypt.hashpw(d["clave"].encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    ip = _client_ip(request)
    u = Usuario.objects.create(
        username=username,
        password_hash=pw_hash,
        nombre=d["nombre"].strip(),
        apellido=d["apellido"].strip(),
        fecha_nacimiento=d["fecha_nacimiento"],
        email=((d.get("email") or "").strip() or None),
        telefono=((d.get("telefono") or "").strip() or None),
        estado="pendiente",
        nivel=1,
        is_active=True,
        sec_q1=d["sec_q1"].strip(),
        sec_a1_hash=hash_answer(d["sec_a1"]),
        sec_q2=d["sec_q2"].strip(),
        sec_a2_hash=hash_answer(d["sec_a2"]),
        signup_ip_hash=ip_hash(ip),
        signup_ip_enc=encrypt_ip(ip),
    )

    _audit(username, "CREATE", "solicitud_usuario", u.id, before=None, after={"estado": "pendiente"})
    return Response({"ok": True, "detail": "Solicitud enviada. Un administrador la revisará."}, status=status.HTTP_201_CREATED)


@csrf_exempt
@require_http_methods(["POST"])
def login(request):
    logger = logging.getLogger(__name__)
    try:
        body = {}
        if request.body:
            try:
                body = json.loads(request.body.decode())
            except Exception:
                body = {}
        if request.POST:
            for k, v in request.POST.items():
                body.setdefault(k, v)

        username = (body.get("username") or body.get("usuario") or body.get("user") or "").strip()
        password = body.get("password") or body.get("pass") or body.get("clave") or ""

        if not username or not password:
            return JsonResponse(
                {
                    "ok": False,
                    "code": "faltan_credenciales",
                    "detail": "Ingresa usuario y clave.",
                },
                status=400,
            )

        try:
            user = Usuario.objects.get(username__iexact=username)
        except Usuario.DoesNotExist:
            return JsonResponse(
                {
                    "ok": False,
                    "code": "credenciales_invalidas",
                    "detail": "El usuario o la clave no son correctos.",
                },
                status=401,
            )

        if not user.is_active:
            return JsonResponse(
                {
                    "ok": False,
                    "code": "cuenta_inactiva",
                    "detail": "Tu cuenta está inactiva. Contacta a un administrador.",
                },
                status=403,
            )

        # Estados esperados: pendiente | activo | rechazado | baneado
        # Regla nueva: permitimos iniciar sesión si está "pendiente" para que pueda entrar a "Mi cuenta".
        if user.estado not in ("activo", "pendiente"):
            if user.estado == "rechazado":
                return JsonResponse(
                    {
                        "ok": False,
                        "code": "cuenta_rechazada",
                        "detail": "Tu cuenta fue rechazada. Si crees que es un error, contacta a un administrador.",
                    },
                    status=403,
                )
            if user.estado == "baneado":
                return JsonResponse(
                    {
                        "ok": False,
                        "code": "cuenta_baneada",
                        "detail": "Tu cuenta fue bloqueada. Contacta a un administrador.",
                    },
                    status=403,
                )
            return JsonResponse(
                {
                    "ok": False,
                    "code": "cuenta_no_autorizada",
                    "detail": "Tu cuenta no está autorizada para iniciar sesión.",
                },
                status=403,
            )

        if not bcrypt.checkpw(password.encode("utf-8"), (user.password_hash or "").encode("utf-8")):
            return JsonResponse(
                {
                    "ok": False,
                    "code": "credenciales_invalidas",
                    "detail": "El usuario o la clave no son correctos.",
                },
                status=401,
            )

        request.session["usuario_id"] = user.id
        request.session.save()

        session_token = uuid4().hex
        user.session_token = session_token
        user.save(update_fields=["session_token"])
        token = make_token(user.username, user.nivel, user.id, sid=session_token)
        return JsonResponse(
            {
                "ok": True,
                "id": user.id,
                "usuario": user.username,
                "username": user.username,
                "nombre": user.nombre,
                "apellido": user.apellido,
                "email": user.email,
                "telefono": user.telefono,
                "fecha_nacimiento": str(user.fecha_nacimiento),
                "edad": user.edad,
                "estado": user.estado,
                "nivel": user.nivel,
                "is_active": user.is_active,
                "token": token,
                "warning": (
                    "Tu cuenta está pendiente. Solo puedes usar 'Mi cuenta' para corregir datos mientras un administrador aprueba."
                    if user.estado == "pendiente"
                    else ""
                ),
            }
        )
    except Exception:
        logger.exception("Login error")
        return JsonResponse({"ok": False, "code": "error_servidor", "detail": "Error interno."}, status=500)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me(request):
    # Mejor que fase 1: devolvemos detalle del Usuario (sin campos sensibles).
    uid = int(getattr(request.user, "id", 0) or 0)
    u = get_object_or_404(Usuario, pk=uid)
    return Response({"ok": True, "usuario": MeUsuarioSerializer(u).data, "nivel": u.nivel})


@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def me_update(request):
    if bool(getattr(request.user, "limited", False)):
        return Response({"detail": "Acceso limitado: no puedes modificar tu cuenta."}, status=status.HTTP_403_FORBIDDEN)
    uid = int(getattr(request.user, "id", 0) or 0)
    u = get_object_or_404(Usuario, pk=uid)
    ser = MeUsuarioSerializer(instance=u, data=request.data, partial=True)
    ser.is_valid(raise_exception=True)
    ser.save()
    _audit(getattr(request.user, "username", ""), "UPDATE", "me", u.id)
    return Response({"ok": True, "usuario": ser.data})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def me_change_password(request):
    if bool(getattr(request.user, "limited", False)):
        return Response({"detail": "Acceso limitado: no puedes cambiar tu clave."}, status=status.HTTP_403_FORBIDDEN)
    uid = int(getattr(request.user, "id", 0) or 0)
    u = get_object_or_404(Usuario, pk=uid)

    ser = ChangePasswordSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    d = ser.validated_data

    actual = (d.get("actual_clave") or "").encode("utf-8")
    stored = (u.password_hash or "").encode("utf-8")
    try:
        ok = bcrypt.checkpw(actual, stored)
    except Exception:
        ok = False
    if not ok:
        return Response({"detail": "Clave actual incorrecta."}, status=status.HTTP_400_BAD_REQUEST)

    nueva = d.get("nueva_clave") or ""
    u.password_hash = bcrypt.hashpw(nueva.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    u.save(update_fields=["password_hash"])
    _audit(getattr(request.user, "username", ""), "UPDATE", "me_password", u.id, before=None, after={"changed": True})
    return Response({"ok": True})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def me_update_security(request):
    if bool(getattr(request.user, "limited", False)):
        return Response({"detail": "Acceso limitado: no puedes cambiar tus preguntas de seguridad."}, status=status.HTTP_403_FORBIDDEN)
    uid = int(getattr(request.user, "id", 0) or 0)
    u = get_object_or_404(Usuario, pk=uid)

    ser = UpdateSecurityQASerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    d = ser.validated_data

    u.sec_q1 = (d.get("sec_q1") or "").strip()
    u.sec_a1_hash = hash_answer(d.get("sec_a1") or "")
    u.sec_q2 = (d.get("sec_q2") or "").strip()
    u.sec_a2_hash = hash_answer(d.get("sec_a2") or "")
    u.save(update_fields=["sec_q1", "sec_a1_hash", "sec_q2", "sec_a2_hash"])
    _audit(getattr(request.user, "username", ""), "UPDATE", "me_security", u.id, before=None, after={"changed": True})
    return Response({"ok": True, "q1": u.sec_q1, "q2": u.sec_q2})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def me_delete_account(request):
    if bool(getattr(request.user, "limited", False)):
        return Response({"detail": "Acceso limitado: no puedes eliminar tu cuenta."}, status=status.HTTP_403_FORBIDDEN)
    uid = int(getattr(request.user, "id", 0) or 0)
    u = get_object_or_404(Usuario, pk=uid)

    # Regla pedida: admins no pueden eliminarse a sí mismos desde aquí.
    try:
        if int(u.nivel) == 0:
            return Response({"detail": "Un administrador no puede eliminar su propia cuenta."}, status=status.HTTP_400_BAD_REQUEST)
    except Exception:
        return Response({"detail": "Rol inválido."}, status=status.HTTP_400_BAD_REQUEST)

    ser = DeleteAccountSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    password = ser.validated_data.get("password") or ""

    stored = (u.password_hash or "").encode("utf-8")
    try:
        ok = bcrypt.checkpw(password.encode("utf-8"), stored)
    except Exception:
        ok = False
    if not ok:
        return Response({"detail": "Clave incorrecta."}, status=status.HTTP_400_BAD_REQUEST)

    before = {"id": u.id, "username": u.username, "estado": u.estado, "nivel": u.nivel}
    u.delete()
    _audit(before.get("username") or "", "DELETE", "me_account", before.get("id"), before=before, after=None)
    return Response({"ok": True})


@api_view(["POST"])
@permission_classes([AllowAny])
def forgot_start(request):
    rec = _iprec(request)
    blocked, _until = _ip_is_blocked(rec)
    if blocked == "banned":
        return Response({"detail": "Acceso bloqueado. Contacta a un administrador."}, status=status.HTTP_403_FORBIDDEN)
    if blocked == "cooldown":
        return Response({"detail": "Demasiados intentos. Intenta más tarde."}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    username = (request.data.get("usuario") or request.data.get("username") or "").strip()
    u = Usuario.objects.filter(username=username, is_active=True, estado="activo").first()
    if not u:
        return Response({"detail": "No se pudo iniciar el proceso."}, status=status.HTTP_400_BAD_REQUEST)

    # Guardar estado del flujo en sesión (frontend usa credentials: include).
    try:
        request.session["forgot_uid"] = int(u.id)
        request.session["forgot_ok1"] = False
        request.session["forgot_ok2"] = False
        request.session.modified = True
    except Exception:
        # Si no hay sesión disponible, seguimos pero el flujo será más restrictivo.
        pass

    rec.forgot_step = 1
    rec.forgot_fail1 = 0
    rec.forgot_fail2 = 0
    rec.save(update_fields=["forgot_step", "forgot_fail1", "forgot_fail2", "last_seen"])
    # Igual a fase 1
    return Response({"usuario": u.username, "q1": u.sec_q1, "q2": u.sec_q2, "step": 1})


@api_view(["POST"])
@permission_classes([AllowAny])
def forgot_answer1(request):
    rec = _iprec(request)
    blocked, _until = _ip_is_blocked(rec)
    if blocked == "banned":
        return Response({"detail": "Acceso bloqueado. Contacta a un administrador."}, status=status.HTTP_403_FORBIDDEN)
    if blocked == "cooldown":
        return Response({"detail": "Demasiados intentos. Intenta más tarde."}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    username = (request.data.get("usuario") or request.data.get("username") or "").strip()
    a1 = request.data.get("a1") or ""
    u = Usuario.objects.filter(username=username, is_active=True, estado="activo").first()
    if not u:
        return Response({"detail": "No se pudo continuar."}, status=status.HTTP_400_BAD_REQUEST)

    # Requerimos haber iniciado el flujo (en esta misma sesión) para marcar ok1.
    try:
        if int(request.session.get("forgot_uid") or 0) != int(u.id):
            return Response({"detail": "Inicia el proceso primero."}, status=status.HTTP_400_BAD_REQUEST)
    except Exception:
        return Response({"detail": "Inicia el proceso primero."}, status=status.HTTP_400_BAD_REQUEST)

    if rec.forgot_step != 1:
        rec.forgot_step = 1
        rec.save(update_fields=["forgot_step", "last_seen"])

    if not verify_answer(a1, u.sec_a1_hash):
        # Igual a fase 1: cuando pasa a step 2 por 3 fallos, devolvemos 200 con q2.
        if rec.forgot_step == 2:
            return Response({"detail": "Pasando a la pregunta 2.", "step": 2, "q2": u.sec_q2}, status=status.HTTP_200_OK)
        return Response({"detail": "Respuesta incorrecta.", "step": 1}, status=status.HTTP_403_FORBIDDEN)

    # OK pregunta 1.
    try:
        request.session["forgot_ok1"] = True
        request.session.modified = True
    except Exception:
        pass

    rec.forgot_step = 2
    rec.forgot_fail1 = 0
    rec.save(update_fields=["forgot_step", "forgot_fail1", "last_seen"])
    return Response({"ok": True, "step": 2, "q2": u.sec_q2})


@api_view(["POST"])
@permission_classes([AllowAny])
def forgot_answer2(request):
    rec = _iprec(request)
    blocked, _until = _ip_is_blocked(rec)
    if blocked == "banned":
        return Response({"detail": "Acceso bloqueado. Contacta a un administrador."}, status=status.HTTP_403_FORBIDDEN)
    if blocked == "cooldown":
        return Response({"detail": "Demasiados intentos. Intenta más tarde."}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    username = (request.data.get("usuario") or request.data.get("username") or "").strip()
    a2 = request.data.get("a2") or ""
    u = Usuario.objects.filter(username=username, is_active=True, estado="activo").first()
    if not u:
        return Response({"detail": "No se pudo continuar."}, status=status.HTTP_400_BAD_REQUEST)

    # Requerimos haber iniciado el flujo en esta sesión.
    try:
        if int(request.session.get("forgot_uid") or 0) != int(u.id):
            return Response({"detail": "Inicia el proceso primero."}, status=status.HTTP_400_BAD_REQUEST)
        ok1 = bool(request.session.get("forgot_ok1"))
    except Exception:
        return Response({"detail": "Inicia el proceso primero."}, status=status.HTTP_400_BAD_REQUEST)

    if rec.forgot_step != 2:
        rec.forgot_step = 2
        rec.save(update_fields=["forgot_step", "last_seen"])

    if not verify_answer(a2, u.sec_a2_hash):
        # Si ya respondió bien la pregunta 1, permitimos "acceso limitado" al agotar intentos de la 2.
        if ok1:
            rec.forgot_fail2 += 1
            if rec.forgot_fail2 >= 3:
                session_token = uuid4().hex
                u.session_token = session_token
                u.save(update_fields=["session_token"])
                token = make_token(u.username, 1, u.id, limited=True, sid=session_token)
                rec.forgot_round = 0
                rec.forgot_step = 1
                rec.forgot_fail1 = 0
                rec.forgot_fail2 = 0
                rec.save(update_fields=["forgot_round", "forgot_step", "forgot_fail1", "forgot_fail2", "last_seen"])
                try:
                    request.session.pop("forgot_uid", None)
                    request.session.pop("forgot_ok1", None)
                    request.session.pop("forgot_ok2", None)
                    request.session.modified = True
                except Exception:
                    pass
                return Response(
                    {
                        "ok": True,
                        "kind": "auth_limited",
                        "token": token,
                        "usuario": u.username,
                        "nivel": 1,
                        "limited": True,
                        "detail": "Acceso limitado: no podrás entrar a Admin ni cambiar tu clave o preguntas de seguridad.",
                    },
                    status=status.HTTP_200_OK,
                )

            rec.save(update_fields=["forgot_fail2", "last_seen"])
            return Response({"detail": "Respuesta incorrecta."}, status=status.HTTP_403_FORBIDDEN)

        _forgot_fail_policy(rec)
        return Response({"detail": "Respuesta incorrecta."}, status=status.HTTP_403_FORBIDDEN)

    # OK pregunta 2.
    try:
        request.session["forgot_ok2"] = True
        request.session.modified = True
    except Exception:
        pass

    if not ok1:
        # Si solo acertó una (la 2), damos acceso limitado (sin reset de clave).
        session_token = uuid4().hex
        u.session_token = session_token
        u.save(update_fields=["session_token"])
        token = make_token(u.username, 1, u.id, limited=True, sid=session_token)
        rec.forgot_round = 0
        rec.forgot_step = 1
        rec.forgot_fail1 = 0
        rec.forgot_fail2 = 0
        rec.save(update_fields=["forgot_round", "forgot_step", "forgot_fail1", "forgot_fail2", "last_seen"])
        try:
            request.session.pop("forgot_uid", None)
            request.session.pop("forgot_ok1", None)
            request.session.pop("forgot_ok2", None)
            request.session.modified = True
        except Exception:
            pass
        return Response(
            {
                "ok": True,
                "kind": "auth_limited",
                "token": token,
                "usuario": u.username,
                "nivel": 1,
                "limited": True,
                "detail": "Acceso limitado: no podrás entrar a Admin ni cambiar tu clave o preguntas de seguridad.",
            },
            status=status.HTTP_200_OK,
        )

    token = _make_reset_token(u.username, u.id)
    rec.forgot_round = 0
    rec.forgot_step = 1
    rec.forgot_fail1 = 0
    rec.forgot_fail2 = 0
    rec.save(update_fields=["forgot_round", "forgot_step", "forgot_fail1", "forgot_fail2", "last_seen"])
    try:
        request.session.pop("forgot_uid", None)
        request.session.pop("forgot_ok1", None)
        request.session.pop("forgot_ok2", None)
        request.session.modified = True
    except Exception:
        pass
    return Response({"ok": True, "kind": "reset", "token": token, "step": 3})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def support_contacts(request):
    """Contactos de soporte (solo lectura).

    Por seguridad, este endpoint está protegido (requiere login) y solo expone correos
    de admins activos. Si existe settings.SUPPORT_EMAIL, se devuelve también como correo recomendado.
    """

    support_email = getattr(settings, "SUPPORT_EMAIL", "") or ""

    qs = (
        Usuario.objects.filter(nivel=0, is_active=True, estado="activo")
        .exclude(email__isnull=True)
        .exclude(email__exact="")
        .order_by("username")
        .values("username", "email")
    )

    contacts = [{"username": r["username"], "email": r["email"]} for r in qs]
    return Response({"ok": True, "support_email": support_email, "contacts": contacts})


@api_view(["POST"])
@permission_classes([AllowAny])
def forgot_reset(request):
    ser = ResetPasswordSerializer(data=request.data)
    if not ser.is_valid():
        return Response({"detail": "Datos inválidos"}, status=status.HTTP_400_BAD_REQUEST)

    token = ser.validated_data["token"]
    new_pw = ser.validated_data["nueva_clave"]

    if not new_pw or len(new_pw) < 6:
        return Response({"detail": "Clave inválida."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        payload = _decode_reset_token(token)
        uid = int(payload.get("uid"))
    except Exception:
        return Response({"detail": "Token inválido."}, status=status.HTTP_400_BAD_REQUEST)

    u = Usuario.objects.filter(id=uid, is_active=True, estado="activo").first()
    if not u:
        return Response({"detail": "No se pudo cambiar."}, status=status.HTTP_400_BAD_REQUEST)

    u.password_hash = bcrypt.hashpw(new_pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    u.save(update_fields=["password_hash"])

    _audit(u.username, "UPDATE", "usuario", u.id, before=None, after={"password_reset": True})
    return Response({"ok": True})


# Alias para mantener el mismo nombre que fase 1.
@csrf_exempt
@require_http_methods(["POST"])
def reset_password(request):
    return forgot_reset(request)


@api_view(["GET"])
@permission_classes([IsAdminNivel0])
def admin_ip_list(request):
    qs = IpRecord.objects.order_by("-last_seen")
    records = list(qs)

    ip_hashes = [r.ip_hash for r in records]
    accounts_by_hash: dict[str, list[dict]] = {h: [] for h in ip_hashes}
    seen_pair: set[tuple[str, int]] = set()
    if ip_hashes:
        users = Usuario.objects.filter(Q(signup_ip_hash__in=ip_hashes) | Q(last_login_ip_hash__in=ip_hashes)).values(
            "id",
            "username",
            "signup_ip_hash",
            "last_login_ip_hash",
        )
        for u in users:
            uid = int(u.get("id") or 0)
            uname = u.get("username") or ""
            for h in (u.get("signup_ip_hash"), u.get("last_login_ip_hash")):
                if not h or h not in accounts_by_hash:
                    continue
                key = (h, uid)
                if key in seen_pair:
                    continue
                seen_pair.add(key)
                accounts_by_hash[h].append({"id": uid, "username": uname})

    items = IpRecordSerializer(records, many=True).data
    # Adjuntar cuentas asociadas (por hash) manteniendo orden.
    for i, rec in enumerate(records):
        try:
            items[i]["accounts"] = accounts_by_hash.get(rec.ip_hash, [])
        except Exception:
            pass

    return Response({"items": items})


@api_view(["POST"])
@permission_classes([IsAdminNivel0])
def admin_ip_ban(request):
    ok, admin_or_resp = _require_admin_password(request)
    if not ok:
        return admin_or_resp

    ip = (request.data.get("ip") or "").strip()
    if not ip:
        return Response({"detail": "ip requerida"}, status=status.HTTP_400_BAD_REQUEST)

    # Nunca permitir autobaneo: ni tu IP actual ni IPs asociadas a tu cuenta.
    requester_ip = _client_ip(request)
    if requester_ip and ip == requester_ip:
        return Response({"detail": "No puedes banear tu propia IP actual."}, status=status.HTTP_400_BAD_REQUEST)

    admin_user = admin_or_resp
    try:
        admin_signup_ip = decrypt_ip(admin_user.signup_ip_enc or "") if admin_user.signup_ip_enc else ""
    except Exception:
        admin_signup_ip = ""
    try:
        admin_last_ip = decrypt_ip(admin_user.last_login_ip_enc or "") if admin_user.last_login_ip_enc else ""
    except Exception:
        admin_last_ip = ""
    if ip and (ip == admin_signup_ip or ip == admin_last_ip):
        return Response({"detail": "No puedes banear una IP asociada a tu cuenta."}, status=status.HTTP_400_BAD_REQUEST)

    h = ip_hash(ip)
    rec = IpRecord.objects.filter(ip_hash=h).first()
    if not rec:
        gh = geo_hint(ip)
        rec = IpRecord.objects.create(ip_hash=h, ip_enc=encrypt_ip(ip), geo_country=gh.country, geo_region=gh.region)

    rec.estado = IpRecord.Estado.BANNED
    rec.cooldown_until = None
    rec.save(update_fields=["estado", "cooldown_until", "last_seen"])
    _audit(getattr(request.user, "username", ""), "BAN", "ip", rec.id, before=None, after={"estado": "banned"})
    return Response({"ok": True})


@api_view(["POST"])
@permission_classes([IsAdminNivel0])
def admin_ip_unban(request):
    ok, admin_or_resp = _require_admin_password(request)
    if not ok:
        return admin_or_resp

    ip = (request.data.get("ip") or "").strip()
    if not ip:
        return Response({"detail": "ip requerida"}, status=status.HTTP_400_BAD_REQUEST)
    h = ip_hash(ip)
    rec = IpRecord.objects.filter(ip_hash=h).first()
    if not rec:
        return Response({"detail": "No existe"}, status=status.HTTP_404_NOT_FOUND)

    rec.estado = IpRecord.Estado.OK
    rec.cooldown_until = None
    rec.login_fails = 0
    rec.login_stage = 0
    rec.forgot_round = 0
    rec.forgot_step = 1
    rec.forgot_fail1 = 0
    rec.forgot_fail2 = 0
    rec.save(
        update_fields=[
            "estado",
            "cooldown_until",
            "login_fails",
            "login_stage",
            "forgot_round",
            "forgot_step",
            "forgot_fail1",
            "forgot_fail2",
            "last_seen",
        ]
    )
    _audit(getattr(request.user, "username", ""), "UNBAN", "ip", rec.id, before=None, after={"estado": "ok"})
    return Response({"ok": True})


@api_view(["GET"])
@permission_classes([IsEstadoActivo])
def materiales_list(request):
    def _to_bool_param(v):
        s = ("" if v is None else str(v)).strip().lower()
        if s in ("1", "true", "si", "sí", "yes"):
            return True
        if s in ("0", "false", "no"):
            return False
        return None

    q = (request.query_params.get("q") or "").strip()
    logic = (request.query_params.get("logic") or "and").strip().lower()
    tipo = (request.query_params.get("tipo") or "").strip()
    ubicacion = (request.query_params.get("ubicacion") or "").strip()

    propio = _to_bool_param(request.query_params.get("propio"))
    vendible = _to_bool_param(request.query_params.get("vendible"))

    low_stock = (request.query_params.get("low_stock") or "").strip().lower() in ("1", "true", "si", "sí")

    cantidad_gte = request.query_params.get("cantidad_gte")
    cantidad_lte = request.query_params.get("cantidad_lte")
    minimo_gte = request.query_params.get("minimo_gte")
    minimo_lte = request.query_params.get("minimo_lte")
    en_uso_gte = request.query_params.get("en_uso_gte")
    en_uso_lte = request.query_params.get("en_uso_lte")

    sort = (request.query_params.get("sort") or "nombre").strip()
    order = (request.query_params.get("order") or "asc").strip().lower()

    try:
        page = int(request.query_params.get("page") or 1)
    except Exception:
        page = 1
    try:
        page_size = int(request.query_params.get("page_size") or 25)
    except Exception:
        page_size = 25

    page = max(1, page)
    page_size = max(5, min(200, page_size))

    qs = Material.objects.all()

    # Construir condiciones para AND/OR (modo profesional de filtrado)
    conds = []
    if q:
        conds.append(Q(nombre__icontains=q) | Q(tipo__icontains=q) | Q(ubicacion__icontains=q))
    if tipo:
        # Cambiamos a icontains para que funcione como filtro real (no solo match exacto)
        conds.append(Q(tipo__icontains=tipo))
    if ubicacion:
        conds.append(Q(ubicacion__icontains=ubicacion))
    if propio is not None:
        conds.append(Q(propio=propio))
    if vendible is not None:
        conds.append(Q(vendible=vendible))
    if low_stock:
        conds.append(Q(cantidad__lte=F("minimo")))

    if cantidad_gte not in (None, ""):
        conds.append(Q(cantidad__gte=_to_dec(cantidad_gte)))
    if cantidad_lte not in (None, ""):
        conds.append(Q(cantidad__lte=_to_dec(cantidad_lte)))
    if minimo_gte not in (None, ""):
        conds.append(Q(minimo__gte=_to_dec(minimo_gte)))
    if minimo_lte not in (None, ""):
        conds.append(Q(minimo__lte=_to_dec(minimo_lte)))
    if en_uso_gte not in (None, ""):
        conds.append(Q(en_uso__gte=_to_dec(en_uso_gte)))
    if en_uso_lte not in (None, ""):
        conds.append(Q(en_uso__lte=_to_dec(en_uso_lte)))

    if conds:
        if logic == "or":
            q_or = Q()
            for c in conds:
                q_or |= c
            qs = qs.filter(q_or)
        else:
            for c in conds:
                qs = qs.filter(c)

    sort_map = {
        "id": "id",
        "nombre": "nombre",
        "tipo": "tipo",
        "precio": "precio",
        "precio_venta": "precio_venta",
        "cantidad": "cantidad",
        "en_uso": "en_uso",
        "minimo": "minimo",
        "vendible": "vendible",
        "propio": "propio",
        "ubicacion": "ubicacion",
        "updated_at": "updated_at",
    }
    sort_field = sort_map.get(sort, "nombre")
    if order == "desc":
        sort_field = "-" + sort_field

    qs = qs.order_by(sort_field)

    total = qs.count()
    pages = (total + page_size - 1) // page_size

    items = qs[(page - 1) * page_size : (page - 1) * page_size + page_size]
    return Response(
        {
            "materiales": MaterialSerializer(items, many=True).data,
            "tipos": list(
                Material.objects.exclude(tipo="").values_list("tipo", flat=True).distinct().order_by("tipo")
            ),
            "page": {"page": page, "page_size": page_size, "filtered_total": total, "pages": pages},
        }
    )


@api_view(["POST"])
@permission_classes([IsEstadoActivo])
def materiales_create(request):
    ser = MaterialSerializer(data=request.data)
    if not ser.is_valid():
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)
    m = ser.save()
    _audit(getattr(request.user, "username", ""), "CREATE", "material", m.id, before=None, after=MaterialSerializer(m).data)
    return Response(MaterialSerializer(m).data, status=status.HTTP_201_CREATED)


@api_view(["PUT", "PATCH", "POST"])
@permission_classes([IsEstadoActivo])
def materiales_update(request, mat_id: int):
    m = Material.objects.filter(id=mat_id).first()
    if not m:
        return Response({"detail": "No existe"}, status=status.HTTP_404_NOT_FOUND)
    before = MaterialSerializer(m).data
    ser = MaterialSerializer(m, data=request.data, partial=request.method in ("PATCH", "POST"))
    if not ser.is_valid():
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)
    m = ser.save()
    _audit(getattr(request.user, "username", ""), "UPDATE", "material", m.id, before=before, after=MaterialSerializer(m).data)
    return Response({"ok": True})


@api_view(["DELETE", "POST"])
@permission_classes([IsEstadoActivo])
def materiales_delete(request, mat_id: int):
    m = Material.objects.filter(id=mat_id).first()
    if not m:
        return Response({"detail": "No existe"}, status=status.HTTP_404_NOT_FOUND)
    before = MaterialSerializer(m).data
    m.delete()
    _audit(getattr(request.user, "username", ""), "DELETE", "material", mat_id, before=before, after=None)
    return Response({"ok": True})


@api_view(["GET"])
@permission_classes([IsEstadoActivo])
def materiales_export_csv(request):
    def _to_bool_param(v):
        s = ("" if v is None else str(v)).strip().lower()
        if s in ("1", "true", "si", "sí", "yes"):
            return True
        if s in ("0", "false", "no"):
            return False
        return None

    scope = (request.query_params.get("scope") or "").strip().lower()

    q = (request.query_params.get("q") or "").strip()
    logic = (request.query_params.get("logic") or "and").strip().lower()
    tipo = (request.query_params.get("tipo") or "").strip()
    ubicacion = (request.query_params.get("ubicacion") or "").strip()
    propio = _to_bool_param(request.query_params.get("propio"))
    vendible = _to_bool_param(request.query_params.get("vendible"))

    low_stock = (request.query_params.get("low_stock") or "").strip().lower() in ("1", "true", "si", "sí")

    cantidad_gte = request.query_params.get("cantidad_gte")
    cantidad_lte = request.query_params.get("cantidad_lte")
    minimo_gte = request.query_params.get("minimo_gte")
    minimo_lte = request.query_params.get("minimo_lte")
    en_uso_gte = request.query_params.get("en_uso_gte")
    en_uso_lte = request.query_params.get("en_uso_lte")
    sort = (request.query_params.get("sort") or "").strip()
    order = (request.query_params.get("order") or "").strip().lower()

    qs = Material.objects.all()

    if scope not in ("all", "todo"):
        conds = []
        if q:
            conds.append(Q(nombre__icontains=q) | Q(tipo__icontains=q) | Q(ubicacion__icontains=q))
        if tipo:
            conds.append(Q(tipo__icontains=tipo))
        if ubicacion:
            conds.append(Q(ubicacion__icontains=ubicacion))
        if propio is not None:
            conds.append(Q(propio=propio))
        if vendible is not None:
            conds.append(Q(vendible=vendible))
        if low_stock:
            conds.append(Q(cantidad__lte=F("minimo")))

        if cantidad_gte not in (None, ""):
            conds.append(Q(cantidad__gte=_to_dec(cantidad_gte)))
        if cantidad_lte not in (None, ""):
            conds.append(Q(cantidad__lte=_to_dec(cantidad_lte)))
        if minimo_gte not in (None, ""):
            conds.append(Q(minimo__gte=_to_dec(minimo_gte)))
        if minimo_lte not in (None, ""):
            conds.append(Q(minimo__lte=_to_dec(minimo_lte)))
        if en_uso_gte not in (None, ""):
            conds.append(Q(en_uso__gte=_to_dec(en_uso_gte)))
        if en_uso_lte not in (None, ""):
            conds.append(Q(en_uso__lte=_to_dec(en_uso_lte)))

        if conds:
            if logic == "or":
                q_or = Q()
                for c in conds:
                    q_or |= c
                qs = qs.filter(q_or)
            else:
                for c in conds:
                    qs = qs.filter(c)

    sort_map = {
        "id": "id",
        "nombre": "nombre",
        "tipo": "tipo",
        "precio": "precio",
        "precio_venta": "precio_venta",
        "cantidad": "cantidad",
        "en_uso": "en_uso",
        "minimo": "minimo",
        "vendible": "vendible",
        "propio": "propio",
        "ubicacion": "ubicacion",
        "updated_at": "updated_at",
    }
    sort_field = sort_map.get(sort, "nombre")
    if order == "desc":
        sort_field = "-" + sort_field
    qs = qs.order_by(sort_field)

    # Excel (Windows) suele abrir mejor CSV con:
    # - BOM UTF-8 para acentos
    # - separador ';' (muchas configuraciones regionales)
    # - línea 'sep=;' para que Excel detecte el separador
    buff = io.StringIO()
    buff.write("\ufeff")
    buff.write("sep=;\n")
    w = csv.writer(buff, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    w.writerow(
        [
            "ID",
            "Nombre",
            "Tipo",
            "Unidad",
            "Disponible",
            "En uso",
            "Mínimo",
            "Costo unitario",
            "Vendible",
            "Precio venta",
            "Ubicación",
            "Propio",
            "Actualizado",
        ]
    )
    for m in qs:
        w.writerow(
            [
                m.id,
                m.nombre,
                m.tipo,
                m.unidad,
                m.cantidad,
                m.en_uso,
                m.minimo,
                str(m.precio),
                "Sí" if getattr(m, "vendible", False) else "No",
                str(getattr(m, "precio_venta", "0")),
                m.ubicacion,
                "Sí" if m.propio else "No",
                m.updated_at.isoformat(),
            ]
        )

    resp = HttpResponse(buff.getvalue(), content_type="text/csv; charset=utf-8-sig")
    resp["Content-Disposition"] = 'attachment; filename="materiales.csv"'
    return resp


@api_view(["GET"])
@permission_classes([IsEstadoActivo])
def materiales_usos_list(request):
    estado = (request.query_params.get("estado") or "abierto").strip() or "abierto"
    q = (request.query_params.get("q") or "").strip()

    qs = MaterialUso.objects.all().order_by("-created_at")
    if estado in ("abierto", "cerrado", "cancelado"):
        qs = qs.filter(estado=estado)
    if q:
        qs = qs.filter(Q(responsable__icontains=q) | Q(destino__icontains=q) | Q(notas__icontains=q))

    try:
        page = int(request.query_params.get("page") or 1)
    except Exception:
        page = 1
    try:
        page_size = int(request.query_params.get("page_size") or 25)
    except Exception:
        page_size = 25
    page = max(1, page)
    page_size = max(5, min(100, page_size))

    total = qs.count()
    pages = (total + page_size - 1) // page_size
    items = qs[(page - 1) * page_size : (page - 1) * page_size + page_size]

    # Lista ligera: sin items completos (para no inflar payload)
    data = []
    for u in items:
        data.append(
            {
                "id": u.id,
                "estado": u.estado,
                "responsable": u.responsable,
                "destino": u.destino,
                "notas": u.notas,
                "created_at": u.created_at,
                "closed_at": u.closed_at,
                "items_count": u.items.count(),
            }
        )

    return Response({"items": data, "page": {"page": page, "page_size": page_size, "total": total, "pages": pages}})


@api_view(["GET"])
@permission_classes([IsEstadoActivo])
def materiales_usos_export_csv(request):
    scope = (request.query_params.get("scope") or "").strip().lower()
    estado = (request.query_params.get("estado") or "").strip()
    q = (request.query_params.get("q") or "").strip()

    qs = MaterialUso.objects.all().order_by("-created_at")
    if scope not in ("all", "todo"):
        if estado in ("abierto", "cerrado", "cancelado"):
            qs = qs.filter(estado=estado)
        if q:
            qs = qs.filter(Q(responsable__icontains=q) | Q(destino__icontains=q) | Q(notas__icontains=q))

    items = (
        MaterialUsoItem.objects.select_related("uso", "material")
        .filter(uso__in=qs)
        .order_by("-uso__created_at", "uso_id", "material_id")
    )

    buff = io.StringIO()
    buff.write("\ufeff")
    buff.write("sep=;\n")
    w = csv.writer(buff, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    w.writerow(
        [
            "Uso ID",
            "Estado",
            "Creado",
            "Cerrado",
            "Responsable",
            "Destino",
            "Notas",
            "Material",
            "Tipo material",
            "Unidad",
            "Salida",
            "Devuelto",
            "Consumido",
            "Roto",
            "Perdido",
            "Pendiente",
        ]
    )

    for it in items:
        uso = it.uso
        m = it.material
        salida = _to_dec(it.cantidad_salida)
        dev = _to_dec(it.cantidad_devuelta)
        cons = _to_dec(it.cantidad_consumida)
        roto = _to_dec(it.cantidad_rota)
        perd = _to_dec(it.cantidad_perdida)
        pendiente = salida - (dev + cons + roto + perd)
        if pendiente < 0:
            pendiente = Decimal("0")
        w.writerow(
            [
                uso.id,
                uso.estado,
                uso.created_at.isoformat() if uso.created_at else "",
                uso.closed_at.isoformat() if uso.closed_at else "",
                uso.responsable,
                uso.destino,
                uso.notas,
                m.nombre if m else "",
                m.tipo if m else "",
                m.unidad if m else "",
                str(salida),
                str(dev),
                str(cons),
                str(roto),
                str(perd),
                str(pendiente),
            ]
        )

    resp = HttpResponse(buff.getvalue(), content_type="text/csv; charset=utf-8-sig")
    resp["Content-Disposition"] = 'attachment; filename="usos.csv"'
    return resp


@api_view(["GET"])
@permission_classes([IsEstadoActivo])
def materiales_usos_detail(request, uso_id: int):
    u = MaterialUso.objects.filter(id=uso_id).first()
    if not u:
        return Response({"detail": "No existe"}, status=status.HTTP_404_NOT_FOUND)
    return Response(MaterialUsoSerializer(u).data)


@api_view(["POST"])
@permission_classes([IsEstadoActivo])
def materiales_usos_create(request):
    responsable = (request.data.get("responsable") or "").strip()
    destino = (request.data.get("destino") or "").strip()
    notas = (request.data.get("notas") or "").strip()
    items = request.data.get("items") or []
    if not isinstance(items, list) or not items:
        return Response({"detail": "items requerido"}, status=status.HTTP_400_BAD_REQUEST)

    # Normalizar y agrupar por material
    req_by_material = {}
    for it in items:
        try:
            mid = int((it or {}).get("material_id") or 0)
        except Exception:
            mid = 0
        qty = _dec_round(_dec_nonneg(_to_dec((it or {}).get("cantidad"), Decimal("0"))))
        if mid <= 0 or qty <= 0:
            continue
        req_by_material[mid] = req_by_material.get(mid, Decimal("0")) + qty

    if not req_by_material:
        return Response({"detail": "items inválidos"}, status=status.HTTP_400_BAD_REQUEST)

    actor = getattr(request.user, "username", "") or ""
    actor_id = int(getattr(request.user, "id", 0) or 0)

    with transaction.atomic():
        mats = {m.id: m for m in Material.objects.select_for_update().filter(id__in=list(req_by_material.keys()))}
        missing = [mid for mid in req_by_material.keys() if mid not in mats]
        if missing:
            return Response({"detail": f"Material(es) no existe(n): {missing}"}, status=status.HTTP_400_BAD_REQUEST)

        # Validar stock
        for mid, qty in req_by_material.items():
            m = mats[mid]
            if _to_dec(m.cantidad, Decimal("0")) < qty:
                return Response(
                    {
                        "detail": f"Stock insuficiente para '{m.nombre}'. Disponible={m.cantidad} {m.unidad}, solicitado={qty} {m.unidad}"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        uso = MaterialUso.objects.create(
            creado_por=Usuario.objects.filter(id=actor_id).first() if actor_id else None,
            responsable=responsable or actor,
            destino=destino,
            notas=notas,
            estado=MaterialUso.Estado.ABIERTO,
        )

        # Aplicar salida + movimientos
        for mid, qty in req_by_material.items():
            m = mats[mid]
            MaterialUsoItem.objects.create(uso=uso, material=m, cantidad_salida=qty)
            m.cantidad = _dec_round(_to_dec(m.cantidad) - qty)
            m.en_uso = _dec_round(_to_dec(m.en_uso) + qty)
            m.save(update_fields=["cantidad", "en_uso", "updated_at"])
            MaterialMovimiento.objects.create(actor=actor, tipo=MaterialMovimiento.Tipo.SALIDA, material=m, uso=uso, cantidad=qty)

    _audit(actor, "CREATE", "material_uso", uso.id, before=None, after={"estado": uso.estado, "items": len(req_by_material)})
    return Response({"ok": True, "id": uso.id}, status=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([IsEstadoActivo])
def materiales_usos_return(request, uso_id: int):
    items = request.data.get("items") or []
    nota = (request.data.get("nota") or "").strip()
    if not isinstance(items, list) or not items:
        return Response({"detail": "items requerido"}, status=status.HTTP_400_BAD_REQUEST)

    actor = getattr(request.user, "username", "") or ""

    with transaction.atomic():
        uso = MaterialUso.objects.select_for_update().filter(id=uso_id).first()
        if not uso:
            return Response({"detail": "No existe"}, status=status.HTTP_404_NOT_FOUND)
        if uso.estado != MaterialUso.Estado.ABIERTO:
            return Response({"detail": "El uso no está abierto"}, status=status.HTTP_400_BAD_REQUEST)

        uso_items = {ui.material_id: ui for ui in MaterialUsoItem.objects.select_for_update().filter(uso=uso)}

        # Agrupar devoluciones por material
        ret_by_mid = {}
        for it in items:
            try:
                mid = int((it or {}).get("material_id") or 0)
            except Exception:
                mid = 0
            if mid <= 0 or mid not in uso_items:
                continue

            dev = _dec_round(_dec_nonneg(_to_dec((it or {}).get("devuelto"), Decimal("0"))))
            cons = _dec_round(_dec_nonneg(_to_dec((it or {}).get("consumido"), Decimal("0"))))
            roto = _dec_round(_dec_nonneg(_to_dec((it or {}).get("roto"), Decimal("0"))))
            perd = _dec_round(_dec_nonneg(_to_dec((it or {}).get("perdido"), Decimal("0"))))

            total = dev + cons + roto + perd
            if total <= 0:
                continue

            prev = ret_by_mid.get(mid) or {"dev": Decimal("0"), "cons": Decimal("0"), "roto": Decimal("0"), "perd": Decimal("0")}
            prev["dev"] += dev
            prev["cons"] += cons
            prev["roto"] += roto
            prev["perd"] += perd
            ret_by_mid[mid] = prev

        if not ret_by_mid:
            return Response({"detail": "items inválidos"}, status=status.HTTP_400_BAD_REQUEST)

        mats = {m.id: m for m in Material.objects.select_for_update().filter(id__in=list(ret_by_mid.keys()))}

        for mid, parts in ret_by_mid.items():
            ui = uso_items[mid]
            m = mats[mid]

            salida = _to_dec(ui.cantidad_salida)
            ya = _to_dec(ui.cantidad_devuelta) + _to_dec(ui.cantidad_consumida) + _to_dec(ui.cantidad_rota) + _to_dec(ui.cantidad_perdida)
            disp = salida - ya
            req_total = parts["dev"] + parts["cons"] + parts["roto"] + parts["perd"]
            if req_total > disp:
                return Response(
                    {
                        "detail": f"Cantidad excede lo pendiente para '{m.nombre}'. Pendiente={disp} {m.unidad}, recibido={req_total} {m.unidad}"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Actualizar item del uso
            ui.cantidad_devuelta = _dec_round(_to_dec(ui.cantidad_devuelta) + parts["dev"])
            ui.cantidad_consumida = _dec_round(_to_dec(ui.cantidad_consumida) + parts["cons"])
            ui.cantidad_rota = _dec_round(_to_dec(ui.cantidad_rota) + parts["roto"])
            ui.cantidad_perdida = _dec_round(_to_dec(ui.cantidad_perdida) + parts["perd"])
            ui.save(update_fields=["cantidad_devuelta", "cantidad_consumida", "cantidad_rota", "cantidad_perdida"])

            # Actualizar stock: devuelto vuelve a disponible; todo lo contabilizado sale de en_uso
            total_sale_uso = parts["dev"] + parts["cons"] + parts["roto"] + parts["perd"]
            m.en_uso = _dec_round(_to_dec(m.en_uso) - total_sale_uso)
            if m.en_uso < 0:
                m.en_uso = Decimal("0")
            m.cantidad = _dec_round(_to_dec(m.cantidad) + parts["dev"])
            m.save(update_fields=["cantidad", "en_uso", "updated_at"])

            # Movimientos
            if parts["dev"] > 0:
                MaterialMovimiento.objects.create(
                    actor=actor,
                    tipo=MaterialMovimiento.Tipo.DEVOLUCION,
                    material=m,
                    uso=uso,
                    cantidad=parts["dev"],
                    nota=nota,
                )
            if parts["cons"] > 0:
                MaterialMovimiento.objects.create(
                    actor=actor,
                    tipo=MaterialMovimiento.Tipo.CONSUMO,
                    material=m,
                    uso=uso,
                    cantidad=parts["cons"],
                    nota=nota,
                )
            if parts["roto"] > 0:
                MaterialMovimiento.objects.create(
                    actor=actor,
                    tipo=MaterialMovimiento.Tipo.ROTO,
                    material=m,
                    uso=uso,
                    cantidad=parts["roto"],
                    nota=nota,
                )
            if parts["perd"] > 0:
                MaterialMovimiento.objects.create(
                    actor=actor,
                    tipo=MaterialMovimiento.Tipo.PERDIDO,
                    material=m,
                    uso=uso,
                    cantidad=parts["perd"],
                    nota=nota,
                )

        # Auto-cerrar si todo quedó contabilizado
        open_left = MaterialUsoItem.objects.filter(uso=uso).exclude(
            cantidad_salida=F("cantidad_devuelta") + F("cantidad_consumida") + F("cantidad_rota") + F("cantidad_perdida")
        ).count()
        if open_left == 0:
            uso.estado = MaterialUso.Estado.CERRADO
            uso.closed_at = dj_timezone.now()
            uso.save(update_fields=["estado", "closed_at"])

    _audit(actor, "UPDATE", "material_uso", uso_id, before=None, after={"action": "return"})
    return Response({"ok": True})


@api_view(["GET"])
@permission_classes([IsEstadoActivo])
def materiales_movimientos_list(request):
    try:
        page = int(request.query_params.get("page") or 1)
    except Exception:
        page = 1
    try:
        page_size = int(request.query_params.get("page_size") or 25)
    except Exception:
        page_size = 25
    page = max(1, page)
    page_size = max(5, min(200, page_size))

    tipo = (request.query_params.get("tipo") or "").strip()
    q = (request.query_params.get("q") or "").strip()

    qs = MaterialMovimiento.objects.select_related("material").all().order_by("-ts")
    if tipo:
        qs = qs.filter(tipo=tipo)
    if q:
        qs = qs.filter(Q(material__nombre__icontains=q) | Q(actor__icontains=q) | Q(nota__icontains=q))

    total = qs.count()
    pages = (total + page_size - 1) // page_size
    items = qs[(page - 1) * page_size : (page - 1) * page_size + page_size]

    return Response(
        {
            "items": MaterialMovimientoSerializer(items, many=True).data,
            "page": {"page": page, "page_size": page_size, "total": total, "pages": pages},
        }
    )


@api_view(["GET"])
@permission_classes([IsEstadoActivo])
def materiales_movimientos_export_csv(request):
    scope = (request.query_params.get("scope") or "").strip().lower()
    tipo = (request.query_params.get("tipo") or "").strip()
    q = (request.query_params.get("q") or "").strip()

    qs = MaterialMovimiento.objects.select_related("material").all().order_by("-ts")
    if scope not in ("all", "todo"):
        if tipo:
            qs = qs.filter(tipo=tipo)
        if q:
            qs = qs.filter(Q(material__nombre__icontains=q) | Q(actor__icontains=q) | Q(nota__icontains=q))

    buff = io.StringIO()
    buff.write("\ufeff")
    buff.write("sep=;\n")
    w = csv.writer(buff, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    w.writerow(
        [
            "Fecha",
            "Tipo",
            "Material",
            "Tipo material",
            "Unidad",
            "Cantidad",
            "Actor",
            "Nota",
            "Uso ID",
            "Costo unitario (actual)",
            "Costo total (estimado)",
        ]
    )

    for mv in qs:
        m = mv.material
        qty = _to_dec(mv.cantidad)
        costo_u = _to_dec(getattr(m, "precio", 0), Decimal("0")) if m else Decimal("0")
        costo_total = qty * costo_u
        w.writerow(
            [
                mv.ts.isoformat() if mv.ts else "",
                mv.tipo,
                m.nombre if m else "",
                m.tipo if m else "",
                m.unidad if m else "",
                str(qty),
                mv.actor,
                mv.nota,
                mv.uso_id or "",
                str(costo_u.quantize(Decimal("0.01"))),
                str(costo_total.quantize(Decimal("0.01"))),
            ]
        )

    resp = HttpResponse(buff.getvalue(), content_type="text/csv; charset=utf-8-sig")
    resp["Content-Disposition"] = 'attachment; filename="movimientos.csv"'
    return resp


@api_view(["GET"])
@permission_classes([IsEstadoActivo])
def materiales_ventas_list(request):
    """Lista ventas (control interno). No es POS: no guarda cliente/vendedor/recibos."""
    q = (request.query_params.get("q") or "").strip()

    try:
        page = int(request.query_params.get("page") or 1)
    except Exception:
        page = 1
    try:
        page_size = int(request.query_params.get("page_size") or 25)
    except Exception:
        page_size = 25
    page = max(1, page)
    page_size = max(5, min(100, page_size))

    qs = MaterialVenta.objects.all().order_by("-created_at")
    if q:
        qs = qs.filter(Q(notas__icontains=q) | Q(items__material__nombre__icontains=q)).distinct()

    total = qs.count()
    pages = (total + page_size - 1) // page_size
    items = qs[(page - 1) * page_size : (page - 1) * page_size + page_size]

    # Cargar items para calcular totales sin N+1 excesivo
    ventas = MaterialVenta.objects.filter(id__in=[v.id for v in items]).prefetch_related("items", "items__material")
    data = MaterialVentaSerializer(ventas, many=True).data

    # Totales del filtro (no del page) para tarjetas de resumen
    total_venta = Decimal("0")
    total_costo = Decimal("0")
    try:
        all_items = MaterialVentaItem.objects.select_related("venta").filter(venta__in=qs)
        for it in all_items:
            qty = _to_dec(it.cantidad)
            total_venta += qty * _to_dec(it.precio_venta_unitario)
            total_costo += qty * _to_dec(it.costo_unitario)
    except Exception:
        pass

    return Response(
        {
            "items": data,
            "page": {"page": page, "page_size": page_size, "total": total, "pages": pages},
            "summary": {"total_venta": float(total_venta), "total_costo": float(total_costo), "ganancia_estimada": float(total_venta - total_costo)},
        }
    )


@api_view(["GET"])
@permission_classes([IsEstadoActivo])
def materiales_ventas_export_csv(request):
    scope = (request.query_params.get("scope") or "").strip().lower()
    q = (request.query_params.get("q") or "").strip()

    qs = MaterialVenta.objects.all().order_by("-created_at")
    if scope not in ("all", "todo"):
        if q:
            qs = qs.filter(Q(notas__icontains=q) | Q(items__material__nombre__icontains=q)).distinct()

    items = (
        MaterialVentaItem.objects.select_related("venta", "material", "venta__creado_por")
        .filter(venta__in=qs)
        .order_by("-venta__created_at", "venta_id", "material_id")
    )

    buff = io.StringIO()
    buff.write("\ufeff")
    buff.write("sep=;\n")
    w = csv.writer(buff, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    w.writerow(
        [
            "Venta ID",
            "Fecha",
            "Creado por",
            "Notas",
            "Material",
            "Tipo material",
            "Unidad",
            "Cantidad",
            "Costo unitario (snapshot)",
            "Precio venta unitario (snapshot)",
            "Total venta",
            "Total costo",
            "Ganancia est.",
        ]
    )

    for it in items:
        v = it.venta
        m = it.material
        qty = _to_dec(it.cantidad)
        cu = _to_dec(it.costo_unitario, Decimal("0")).quantize(Decimal("0.01"))
        pv = _to_dec(it.precio_venta_unitario, Decimal("0")).quantize(Decimal("0.01"))
        tv = (qty * pv).quantize(Decimal("0.01"))
        tc = (qty * cu).quantize(Decimal("0.01"))
        w.writerow(
            [
                v.id if v else "",
                v.created_at.isoformat() if v and v.created_at else "",
                getattr(getattr(v, "creado_por", None), "username", "") if v else "",
                v.notas if v else "",
                m.nombre if m else "",
                m.tipo if m else "",
                m.unidad if m else "",
                str(qty),
                str(cu),
                str(pv),
                str(tv),
                str(tc),
                str((tv - tc).quantize(Decimal("0.01"))),
            ]
        )

    resp = HttpResponse(buff.getvalue(), content_type="text/csv; charset=utf-8-sig")
    resp["Content-Disposition"] = 'attachment; filename="ventas.csv"'
    return resp


@api_view(["GET"])
@permission_classes([IsEstadoActivo])
def materiales_ventas_detail(request, venta_id: int):
    v = MaterialVenta.objects.filter(id=venta_id).prefetch_related("items", "items__material").first()
    if not v:
        return Response({"detail": "No existe"}, status=status.HTTP_404_NOT_FOUND)
    return Response(MaterialVentaSerializer(v).data)


@api_view(["POST"])
@permission_classes([IsEstadoActivo])
def materiales_ventas_create(request):
    notas = (request.data.get("notas") or "").strip()
    items = request.data.get("items") or []
    if not isinstance(items, list) or not items:
        return Response({"detail": "items requerido"}, status=status.HTTP_400_BAD_REQUEST)

    # Normalizar y agrupar por material
    req_by_material = {}
    price_by_material = {}
    for it in items:
        try:
            mid = int((it or {}).get("material_id") or 0)
        except Exception:
            mid = 0
        qty = _dec_round(_dec_nonneg(_to_dec((it or {}).get("cantidad"), Decimal("0"))))
        if mid <= 0 or qty <= 0:
            continue
        req_by_material[mid] = req_by_material.get(mid, Decimal("0")) + qty

        # Permitir sobrescribir precio de venta unitario por item (opcional)
        pv = (it or {}).get("precio_venta_unitario", None)
        if pv is not None and pv != "":
            price_by_material[mid] = _dec_nonneg(_to_dec(pv, Decimal("0"))).quantize(Decimal("0.01"))

    if not req_by_material:
        return Response({"detail": "items inválidos"}, status=status.HTTP_400_BAD_REQUEST)

    actor = getattr(request.user, "username", "") or ""
    actor_id = int(getattr(request.user, "id", 0) or 0)

    with transaction.atomic():
        mats = {m.id: m for m in Material.objects.select_for_update().filter(id__in=list(req_by_material.keys()))}
        missing = [mid for mid in req_by_material.keys() if mid not in mats]
        if missing:
            return Response({"detail": f"Material(es) no existe(n): {missing}"}, status=status.HTTP_400_BAD_REQUEST)

        # Reglas: solo vendible + propio
        for mid, qty in req_by_material.items():
            m = mats[mid]
            if not getattr(m, "vendible", False):
                return Response({"detail": f"'{m.nombre}' no está marcado como vendible."}, status=status.HTTP_400_BAD_REQUEST)
            if not m.propio:
                return Response({"detail": f"'{m.nombre}' no es inventario propio; no se registran ventas sobre existencias de terceros."}, status=status.HTTP_400_BAD_REQUEST)
            if _to_dec(m.cantidad, Decimal("0")) < qty:
                return Response(
                    {"detail": f"Stock insuficiente para '{m.nombre}'. Disponible={m.cantidad} {m.unidad}, solicitado={qty} {m.unidad}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        venta = MaterialVenta.objects.create(
            creado_por=Usuario.objects.filter(id=actor_id).first() if actor_id else None,
            notas=notas,
        )

        for mid, qty in req_by_material.items():
            m = mats[mid]
            costo_u = _dec_nonneg(_to_dec(m.precio, Decimal("0"))).quantize(Decimal("0.01"))
            pv_u = price_by_material.get(mid)
            if pv_u is None:
                pv_u = _dec_nonneg(_to_dec(getattr(m, "precio_venta", 0), Decimal("0"))).quantize(Decimal("0.01"))

            MaterialVentaItem.objects.create(
                venta=venta,
                material=m,
                cantidad=qty,
                costo_unitario=costo_u,
                precio_venta_unitario=pv_u,
            )

            m.cantidad = _dec_round(_to_dec(m.cantidad) - qty)
            m.save(update_fields=["cantidad", "updated_at"])

            MaterialMovimiento.objects.create(
                actor=actor,
                tipo=MaterialMovimiento.Tipo.VENTA,
                material=m,
                uso=None,
                cantidad=qty,
                nota=(notas[:220] if notas else f"Venta #{venta.id}"),
            )

    _audit(actor, "CREATE", "material_venta", venta.id, before=None, after={"items": len(req_by_material)})
    venta = MaterialVenta.objects.filter(id=venta.id).prefetch_related("items", "items__material").first()
    return Response(MaterialVentaSerializer(venta).data, status=status.HTTP_201_CREATED)


@api_view(["GET"])
@permission_classes([IsAdminNivel0])
def admin_pending_list(request):
    try:
        page = int(request.query_params.get("page") or 1)
    except Exception:
        page = 1
    try:
        page_size = int(request.query_params.get("page_size") or 25)
    except Exception:
        page_size = 25

    page = max(1, page)
    page_size = max(5, min(200, page_size))

    qs = Usuario.objects.filter(estado="pendiente").order_by("created_at")
    total = qs.count()
    pages = (total + page_size - 1) // page_size
    items = qs[(page - 1) * page_size : (page - 1) * page_size + page_size]

    return Response({"items": UsuarioAdminSerializer(items, many=True).data, "page": {"page": page, "page_size": page_size, "total": total, "pages": pages}})


@api_view(["POST"])
@permission_classes([IsAdminNivel0])
def admin_pending_approve(request, user_id: int):
    admin_password = request.data.get("admin_password") or ""
    if not admin_password:
        return Response({"detail": "admin_password requerida"}, status=status.HTTP_400_BAD_REQUEST)

    admin_id = int(getattr(request.user, "id", 0) or 0)
    admin_user = get_object_or_404(Usuario, pk=admin_id)
    stored = (admin_user.password_hash or "").encode("utf-8")
    try:
        ok = bcrypt.checkpw(admin_password.encode("utf-8"), stored)
    except Exception:
        ok = False
    if not ok:
        return Response({"detail": "Clave de administrador incorrecta."}, status=status.HTTP_403_FORBIDDEN)

    u = Usuario.objects.filter(id=user_id).first()
    if not u:
        return Response({"detail": "No existe"}, status=status.HTTP_404_NOT_FOUND)
    if u.estado != "pendiente":
        return Response({"detail": "La solicitud no está pendiente"}, status=status.HTTP_400_BAD_REQUEST)

    before = UsuarioAdminSerializer(u).data
    u.estado = "activo"
    u.save(update_fields=["estado"])
    _audit(getattr(request.user, "username", ""), "UPDATE", "solicitud_usuario", u.id, before=before, after={"estado": "activo"})
    return Response({"ok": True, "estado": u.estado})


@api_view(["POST"])
@permission_classes([IsAdminNivel0])
def admin_pending_reject(request, user_id: int):
    admin_password = request.data.get("admin_password") or ""
    if not admin_password:
        return Response({"detail": "admin_password requerida"}, status=status.HTTP_400_BAD_REQUEST)

    admin_id = int(getattr(request.user, "id", 0) or 0)
    admin_user = get_object_or_404(Usuario, pk=admin_id)
    stored = (admin_user.password_hash or "").encode("utf-8")
    try:
        ok = bcrypt.checkpw(admin_password.encode("utf-8"), stored)
    except Exception:
        ok = False
    if not ok:
        return Response({"detail": "Clave de administrador incorrecta."}, status=status.HTTP_403_FORBIDDEN)

    u = Usuario.objects.filter(id=user_id).first()
    if not u:
        return Response({"detail": "No existe"}, status=status.HTTP_404_NOT_FOUND)
    if u.estado != "pendiente":
        return Response({"detail": "La solicitud no está pendiente"}, status=status.HTTP_400_BAD_REQUEST)

    before = UsuarioAdminSerializer(u).data
    u.estado = "rechazado"
    u.save(update_fields=["estado"])
    _audit(getattr(request.user, "username", ""), "UPDATE", "solicitud_usuario", u.id, before=before, after={"estado": "rechazado"})
    return Response({"ok": True, "estado": u.estado})


@api_view(["GET"])
@permission_classes([IsAdminNivel0])
def admin_users_list(request):
    q = (request.query_params.get("q") or "").strip()
    estado = (request.query_params.get("estado") or "").strip()
    try:
        page = int(request.query_params.get("page") or 1)
    except Exception:
        page = 1
    try:
        page_size = int(request.query_params.get("page_size") or 25)
    except Exception:
        page_size = 25

    page = max(1, page)
    page_size = max(5, min(200, page_size))

    qs = Usuario.objects.order_by("username")
    if estado in ("pendiente", "activo", "rechazado", "baneado"):
        qs = qs.filter(estado=estado)
    if q:
        qs = qs.filter(
            Q(username__icontains=q)
            | Q(nombre__icontains=q)
            | Q(apellido__icontains=q)
            | Q(email__icontains=q)
            | Q(telefono__icontains=q)
        )
    total = qs.count()
    pages = (total + page_size - 1) // page_size
    items = qs[(page - 1) * page_size : (page - 1) * page_size + page_size]

    return Response({"items": UsuarioAdminSerializer(items, many=True).data, "page": {"page": page, "page_size": page_size, "total": total, "pages": pages}})


@api_view(["PATCH"])
@permission_classes([IsAdminNivel0])
def admin_users_update(request, user_id: int):
    u = get_object_or_404(Usuario, pk=user_id)

    admin_id = int(getattr(request.user, "id", 0) or 0)
    wants_sensitive_change = any(k in request.data for k in ("estado", "nivel", "is_active"))
    if wants_sensitive_change and int(user_id) != int(admin_id):
        admin_password = request.data.get("admin_password") or ""
        if not admin_password:
            return Response({"detail": "admin_password requerida"}, status=status.HTTP_400_BAD_REQUEST)
        admin_user = get_object_or_404(Usuario, pk=admin_id)
        stored = (admin_user.password_hash or "").encode("utf-8")
        try:
            ok = bcrypt.checkpw(admin_password.encode("utf-8"), stored)
        except Exception:
            ok = False
        if not ok:
            return Response({"detail": "Clave de administrador incorrecta."}, status=status.HTTP_403_FORBIDDEN)

    data = request.data.copy()
    try:
        data.pop("admin_password", None)
    except Exception:
        try:
            if "admin_password" in data:
                del data["admin_password"]
        except Exception:
            pass

    ser = AdminUsuarioEditSerializer(instance=u, data=data, partial=True)
    ser.is_valid(raise_exception=True)
    before = UsuarioAdminSerializer(u).data
    ser.save()
    _audit(getattr(request.user, "username", ""), "UPDATE", "usuario", u.id, before=before, after=UsuarioAdminSerializer(u).data)
    return Response({"ok": True})


@api_view(["POST"])
@permission_classes([IsAdminNivel0])
def admin_users_create(request):
    ok, admin_or_resp = _require_admin_password(request)
    if not ok:
        return admin_or_resp

    username = (request.data.get("usuario") or request.data.get("username") or "").strip()
    auto_password = bool(request.data.get("auto_password") or request.data.get("generar_clave") or request.data.get("auto"))
    clave = (request.data.get("clave") or request.data.get("password") or "")
    nombre = (request.data.get("nombre") or "").strip()
    apellido = (request.data.get("apellido") or "").strip()
    fecha_nacimiento = request.data.get("fecha_nacimiento")

    estado = (request.data.get("estado") or "activo").strip().lower()

    sec_q1 = (request.data.get("sec_q1") or "").strip()
    sec_a1 = request.data.get("sec_a1") or ""
    sec_q2 = (request.data.get("sec_q2") or "").strip()
    sec_a2 = request.data.get("sec_a2") or ""

    try:
        nivel = int(request.data.get("nivel", 1))
    except Exception:
        nivel = 1

    if estado not in ("activo", "pendiente"):
        return Response({"detail": "estado inválido (activo|pendiente)"}, status=status.HTTP_400_BAD_REQUEST)

    if nivel not in (0, 1):
        return Response({"detail": "nivel inválido (0=admin, 1=usuario)"}, status=status.HTTP_400_BAD_REQUEST)

    if not username or not nombre or not apellido or not fecha_nacimiento:
        return Response({"detail": "Datos incompletos"}, status=status.HTTP_400_BAD_REQUEST)

    if auto_password:
        alphabet = string.ascii_letters + string.digits
        clave = "".join(secrets.choice(alphabet) for _ in range(12))
    if not clave:
        return Response({"detail": "clave requerida"}, status=status.HTTP_400_BAD_REQUEST)

    if not sec_q1 or not sec_a1 or not sec_q2 or not sec_a2:
        return Response({"detail": "Completa 2 preguntas y sus respuestas."}, status=status.HTTP_400_BAD_REQUEST)

    if sec_q1.lower() == sec_q2.lower():
        return Response({"detail": "Las preguntas deben ser diferentes."}, status=status.HTTP_400_BAD_REQUEST)

    if Usuario.objects.filter(username__iexact=username).exists():
        return Response({"detail": "usuario ya existe"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        dob = date.fromisoformat(str(fecha_nacimiento))
    except Exception:
        return Response({"detail": "fecha_nacimiento inválida (YYYY-MM-DD)"}, status=status.HTTP_400_BAD_REQUEST)

    pw_hash = bcrypt.hashpw(clave.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    u = Usuario.objects.create(
        username=username,
        password_hash=pw_hash,
        nombre=nombre,
        apellido=apellido,
        fecha_nacimiento=dob,
        email=(request.data.get("email") or "").strip() or None,
        telefono=(request.data.get("telefono") or "").strip() or None,
        estado=estado,
        nivel=nivel,
        is_active=True,
        sec_q1=sec_q1,
        sec_a1_hash=hash_answer(sec_a1),
        sec_q2=sec_q2,
        sec_a2_hash=hash_answer(sec_a2),
    )

    _audit(getattr(request.user, "username", ""), "CREATE", "usuario", u.id, before=None, after=UsuarioAdminSerializer(u).data)
    resp = {"id": u.id, "usuario": u.username, "estado": u.estado, "nivel": u.nivel}
    if auto_password:
        resp["clave_generada"] = clave
    return Response(resp, status=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([IsAdminNivel0])
def admin_users_reset_password(request, user_id: int):
    clave = request.data.get("clave") or request.data.get("password") or request.data.get("nueva_clave") or ""
    if not clave:
        return Response({"detail": "clave requerida"}, status=status.HTTP_400_BAD_REQUEST)

    u = Usuario.objects.filter(id=user_id).first()
    if not u:
        return Response({"detail": "No existe"}, status=status.HTTP_404_NOT_FOUND)

    before = UsuarioAdminSerializer(u).data
    u.password_hash = bcrypt.hashpw(clave.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    u.save(update_fields=["password_hash"])

    _audit(getattr(request.user, "username", ""), "UPDATE", "usuario", u.id, before=before, after={"password_reset": True})
    return Response({"ok": True})


@api_view(["POST"])
@permission_classes([IsAdminNivel0])
def admin_users_generate_password(request, user_id: int):
    admin_password = request.data.get("admin_password") or ""
    if not admin_password:
        return Response({"detail": "admin_password requerida"}, status=status.HTTP_400_BAD_REQUEST)

    # Re-autenticación: confirmar que quien pide la clave temporal es el admin logueado.
    admin_id = int(getattr(request.user, "id", 0) or 0)
    admin_user = get_object_or_404(Usuario, pk=admin_id)
    stored = (admin_user.password_hash or "").encode("utf-8")
    try:
        ok = bcrypt.checkpw(admin_password.encode("utf-8"), stored)
    except Exception:
        ok = False
    if not ok:
        return Response({"detail": "Clave de administrador incorrecta."}, status=status.HTTP_403_FORBIDDEN)

    u = Usuario.objects.filter(id=user_id).first()
    if not u:
        return Response({"detail": "No existe"}, status=status.HTTP_404_NOT_FOUND)

    # Generar clave temporal (12 chars) y guardarla.
    alphabet = string.ascii_letters + string.digits
    temp = "".join(secrets.choice(alphabet) for _ in range(12))

    before = UsuarioAdminSerializer(u).data
    u.password_hash = bcrypt.hashpw(temp.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    u.save(update_fields=["password_hash"])

    _audit(
        getattr(request.user, "username", ""),
        "UPDATE",
        "usuario",
        u.id,
        before=before,
        after={"password_temp_generated": True},
    )
    # Se devuelve la clave SOLO en este momento.
    return Response({"ok": True, "password": temp})


@api_view(["DELETE", "POST"])
@permission_classes([IsAdminNivel0])
def admin_users_delete(request, user_id: int):
        if u and int(u.id) == 1:
            return Response({"detail": "No puedes eliminar al superadministrador (id=1)."}, status=status.HTTP_400_BAD_REQUEST)
        if u and int(u.id) == 1 and int(admin_id) != 1:
            return Response({"detail": "No puedes modificar al superadministrador (id=1)."}, status=status.HTTP_400_BAD_REQUEST)
        if u and int(u.id) == 1 and int(getattr(request.user, "id", 0)) != 1:
            return Response({"detail": "No puedes cambiar la clave del superadministrador (id=1)."}, status=status.HTTP_400_BAD_REQUEST)
    ok, admin_or_resp = _require_admin_password(request)
    if not ok:
        return admin_or_resp

    u = Usuario.objects.filter(id=user_id).first()
    if not u:
        return Response({"detail": "No existe"}, status=status.HTTP_404_NOT_FOUND)

    if u.username == getattr(request.user, "username", None):
        return Response({"detail": "No puedes eliminar tu propio usuario"}, status=status.HTTP_400_BAD_REQUEST)

    # Regla pedida: no permitir eliminar al último admin.
    try:
        is_target_admin = int(u.nivel) == 0
    except Exception:
        is_target_admin = False
    if is_target_admin:
        other_admin_exists = Usuario.objects.filter(nivel=0, is_active=True).exclude(id=u.id).exists()
        if not other_admin_exists:
            return Response({"detail": "No puedes eliminar al último administrador."}, status=status.HTTP_400_BAD_REQUEST)

    before = UsuarioAdminSerializer(u).data
    u.delete()
    _audit(getattr(request.user, "username", ""), "DELETE", "usuario", user_id, before=before, after=None)
    return Response({"ok": True})


@api_view(["GET"])
@permission_classes([IsAdminNivel0])
def admin_audit_list(request):
    try:
        page = int(request.query_params.get("page") or 1)
    except Exception:
        page = 1
    try:
        page_size = int(request.query_params.get("page_size") or 25)
    except Exception:
        page_size = 25

    page = max(1, page)
    page_size = max(5, min(200, page_size))

    qs = AuditLog.objects.order_by("-ts")
    total = qs.count()
    pages = (total + page_size - 1) // page_size
    items = qs[(page - 1) * page_size : (page - 1) * page_size + page_size]

    data = [
        {
            "id": a.id,
            "ts": a.ts.isoformat(),
            "actor": a.actor,
            "actor_id": a.actor_id,
            "action": a.action,
            "entity": a.entity,
            "entity_id": a.entity_id,
            "before": a.before_json,
            "after": a.after_json,
        }
        for a in items
    ]

    return Response({"items": data, "page": {"page": page, "page_size": page_size, "total": total, "pages": pages}})
