from datetime import date

from rest_framework import serializers

from .models import AuditLog, IpRecord, Material, MaterialMovimiento, MaterialUso, MaterialUsoItem, MaterialVenta, MaterialVentaItem, Usuario
from .security import decrypt_ip


class RegisterRequestSerializer(serializers.Serializer):
    nombre = serializers.CharField(max_length=120)
    apellido = serializers.CharField(max_length=120)
    fecha_nacimiento = serializers.DateField()

    email = serializers.EmailField(required=False, allow_null=True, allow_blank=True)
    telefono = serializers.CharField(required=False, allow_null=True, allow_blank=True, max_length=30)

    usuario = serializers.CharField(max_length=80)
    clave = serializers.CharField(max_length=200)

    sec_q1 = serializers.CharField(max_length=200)
    sec_a1 = serializers.CharField(max_length=200)
    sec_q2 = serializers.CharField(max_length=200)
    sec_a2 = serializers.CharField(max_length=200)

    def validate(self, attrs):
        email = (attrs.get("email") or "").strip()
        tel = (attrs.get("telefono") or "").strip()
        if not email and not tel:
            raise serializers.ValidationError("Debes colocar correo o teléfono (al menos uno).")

        usuario = (attrs.get("usuario") or "").strip()
        if not usuario:
            raise serializers.ValidationError("Usuario requerido.")

        if len((attrs.get("clave") or "")) < 4:
            raise serializers.ValidationError("Clave inválida.")

        if not (attrs.get("sec_q1") or "").strip() or not (attrs.get("sec_a1") or "").strip():
            raise serializers.ValidationError("Debes crear la pregunta de seguridad 1.")
        if not (attrs.get("sec_q2") or "").strip() or not (attrs.get("sec_a2") or "").strip():
            raise serializers.ValidationError("Debes crear la pregunta de seguridad 2.")

        if (attrs.get("sec_q1") or "").strip().lower() == (attrs.get("sec_q2") or "").strip().lower():
            raise serializers.ValidationError("Las preguntas deben ser diferentes.")
        return attrs


class ForgotStartSerializer(serializers.Serializer):
    usuario = serializers.CharField(max_length=80)


class ForgotVerifySerializer(serializers.Serializer):
    usuario = serializers.CharField(max_length=80)
    a1 = serializers.CharField(max_length=200)
    a2 = serializers.CharField(max_length=200)


class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    nueva_clave = serializers.CharField(max_length=200)


class ChangePasswordSerializer(serializers.Serializer):
    actual_clave = serializers.CharField(max_length=200)
    nueva_clave = serializers.CharField(max_length=200)

    def validate(self, attrs):
        new_pw = attrs.get("nueva_clave") or ""
        if len(new_pw) < 6:
            raise serializers.ValidationError({"nueva_clave": "La nueva clave debe tener al menos 6 caracteres."})
        if (attrs.get("actual_clave") or "") == new_pw:
            raise serializers.ValidationError({"nueva_clave": "La nueva clave debe ser distinta a la actual."})
        return attrs


class UpdateSecurityQASerializer(serializers.Serializer):
    sec_q1 = serializers.CharField(max_length=200)
    sec_a1 = serializers.CharField(max_length=200)
    sec_q2 = serializers.CharField(max_length=200)
    sec_a2 = serializers.CharField(max_length=200)

    def validate(self, attrs):
        q1 = (attrs.get("sec_q1") or "").strip()
        a1 = (attrs.get("sec_a1") or "").strip()
        q2 = (attrs.get("sec_q2") or "").strip()
        a2 = (attrs.get("sec_a2") or "").strip()

        if not q1 or not a1:
            raise serializers.ValidationError("Debes completar la pregunta 1 y su respuesta.")

        if not q2 or not a2:
            raise serializers.ValidationError("Debes completar la pregunta 2 y su respuesta.")
        if q1.lower() == q2.lower():
            raise serializers.ValidationError("Las preguntas deben ser diferentes.")
        return attrs


class DeleteAccountSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=1, write_only=True)


class MaterialSerializer(serializers.ModelSerializer):
    class Meta:
        model = Material
        fields = [
            "id",
            "nombre",
            "tipo",
            "unidad",
            "precio",
            "vendible",
            "precio_venta",
            "ubicacion",
            "cantidad",
            "en_uso",
            "minimo",
            "propio",
            "updated_at",
            "created_at",
        ]
        read_only_fields = ["en_uso", "updated_at", "created_at"]

    def validate(self, attrs):
        # Regla de negocio:
        # - "Vendible" y "precio_venta" solo aplican a inventario propio.
        # - Esto evita incoherencias aunque el frontend falle o alguien llame a la API directamente.
        propio = attrs.get("propio")
        vendible = attrs.get("vendible")
        precio_venta = attrs.get("precio_venta")

        if self.instance is not None:
            if propio is None:
                propio = bool(getattr(self.instance, "propio", False))
            if vendible is None:
                vendible = bool(getattr(self.instance, "vendible", False))
            if precio_venta is None:
                precio_venta = getattr(self.instance, "precio_venta", 0)

        propio = bool(propio)
        vendible = bool(vendible)

        try:
            pv = float(precio_venta or 0)
        except Exception:
            pv = 0

        if not propio:
            errors = {}
            if vendible:
                errors["vendible"] = "Solo aplica cuando el material es inventario propio."
            if pv and pv > 0:
                errors["precio_venta"] = "Solo aplica cuando el material es inventario propio."
            if errors:
                raise serializers.ValidationError(errors)

        if pv < 0:
            raise serializers.ValidationError({"precio_venta": "Debe ser mayor o igual a 0."})

        return attrs


class MaterialUsoItemSerializer(serializers.ModelSerializer):
    material = MaterialSerializer(read_only=True)
    material_id = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = MaterialUsoItem
        fields = [
            "id",
            "material",
            "material_id",
            "cantidad_salida",
            "cantidad_devuelta",
            "cantidad_consumida",
            "cantidad_rota",
            "cantidad_perdida",
        ]


class MaterialUsoSerializer(serializers.ModelSerializer):
    items = MaterialUsoItemSerializer(many=True, read_only=True)

    class Meta:
        model = MaterialUso
        fields = [
            "id",
            "estado",
            "responsable",
            "destino",
            "notas",
            "created_at",
            "closed_at",
            "items",
        ]


class MaterialMovimientoSerializer(serializers.ModelSerializer):
    material = MaterialSerializer(read_only=True)

    class Meta:
        model = MaterialMovimiento
        fields = ["id", "ts", "actor", "tipo", "cantidad", "nota", "material", "uso_id"]


class MaterialVentaItemSerializer(serializers.ModelSerializer):
    material = MaterialSerializer(read_only=True)
    material_id = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = MaterialVentaItem
        fields = ["id", "material", "material_id", "cantidad", "costo_unitario", "precio_venta_unitario"]


class MaterialVentaSerializer(serializers.ModelSerializer):
    items = MaterialVentaItemSerializer(many=True, read_only=True)
    total_venta = serializers.SerializerMethodField()
    total_costo = serializers.SerializerMethodField()
    ganancia_estimada = serializers.SerializerMethodField()
    items_count = serializers.SerializerMethodField()

    class Meta:
        model = MaterialVenta
        fields = ["id", "created_at", "notas", "items", "items_count", "total_venta", "total_costo", "ganancia_estimada"]

    def get_items_count(self, obj: MaterialVenta):
        try:
            return obj.items.count()
        except Exception:
            return 0

    def _sum(self, obj: MaterialVenta):
        total_venta = 0
        total_costo = 0
        try:
            for it in obj.items.all():
                qty = float(it.cantidad or 0)
                total_venta += qty * float(it.precio_venta_unitario or 0)
                total_costo += qty * float(it.costo_unitario or 0)
        except Exception:
            pass
        return (total_venta, total_costo)

    def get_total_venta(self, obj: MaterialVenta):
        return round(self._sum(obj)[0], 2)

    def get_total_costo(self, obj: MaterialVenta):
        return round(self._sum(obj)[1], 2)

    def get_ganancia_estimada(self, obj: MaterialVenta):
        tv, tc = self._sum(obj)
        return round(tv - tc, 2)


class AuditLogSerializer(serializers.ModelSerializer):
    actor_id = serializers.SerializerMethodField()

    def get_actor_id(self, obj: AuditLog):
        # Preferimos el dato persistido en DB.
        persisted = getattr(obj, "actor_id", None)
        if persisted is not None:
            return persisted

        # Fallback (por si aún no corrieron migraciones en algún entorno).
        actor = (getattr(obj, "actor", "") or "").strip()
        if not actor or actor.lower() == "system":
            return None
        try:
            u = Usuario.objects.filter(username=actor).only("id").first()
            return u.id if u else None
        except Exception:
            return None

    class Meta:
        model = AuditLog
        fields = ["id", "ts", "actor", "actor_id", "action", "entity", "entity_id", "before_json", "after_json"]


class IpRecordSerializer(serializers.ModelSerializer):
    ip = serializers.SerializerMethodField()

    class Meta:
        model = IpRecord
        fields = [
            "id",
            "estado",
            "cooldown_until",
            "login_stage",
            "login_fails",
            "forgot_round",
            "forgot_step",
            "forgot_fail1",
            "forgot_fail2",
            "geo_country",
            "geo_region",
            "last_seen",
            "created_at",
            "ip",
        ]

    def get_ip(self, obj: IpRecord):
        try:
            return decrypt_ip(obj.ip_enc)
        except Exception:
            return None


class UsuarioSerializer(serializers.ModelSerializer):
    class Meta:
        model = Usuario
        fields = ["id", "username", "nivel", "is_active", "created_at"]


class UsuarioAdminSerializer(serializers.ModelSerializer):
    edad = serializers.SerializerMethodField()
    signup_ip = serializers.SerializerMethodField()
    last_login_ip = serializers.SerializerMethodField()

    class Meta:
        model = Usuario
        fields = [
            "id",
            "username",
            "nombre",
            "apellido",
            "fecha_nacimiento",
            "edad",
            "email",
            "telefono",
            "estado",
            "nivel",
            "is_active",
            "created_at",
            "signup_ip",
            "last_login_ip",
        ]

    def get_edad(self, obj: Usuario):
        try:
            today = date.today()
            b = obj.fecha_nacimiento
            age = today.year - b.year - (1 if (today.month, today.day) < (b.month, b.day) else 0)
            return max(0, age)
        except Exception:
            return None

    def get_signup_ip(self, obj: Usuario):
        try:
            return decrypt_ip(obj.signup_ip_enc or "") if obj.signup_ip_enc else None
        except Exception:
            return None

    def get_last_login_ip(self, obj: Usuario):
        try:
            return decrypt_ip(obj.last_login_ip_enc or "") if obj.last_login_ip_enc else None
        except Exception:
            return None


class AdminUsuarioSerializer(serializers.ModelSerializer):
    edad = serializers.SerializerMethodField()

    class Meta:
        model = Usuario
        fields = [
            "id",
            "username",
            "nombre",
            "apellido",
            "fecha_nacimiento",
            "edad",
            "email",
            "telefono",
            "estado",
            "nivel",
            "is_active",
            "created_at",
            "fecha_nacimiento_change_count",
        ]
        read_only_fields = [
            "username",
            "nombre",
            "apellido",
            "fecha_nacimiento",
            "edad",
            "email",
            "telefono",
            "created_at",
            "fecha_nacimiento_change_count",
        ]

    def get_edad(self, obj):
        return obj.edad

    def update(self, instance, validated_data):
        for field in ("estado", "nivel", "is_active"):
            if field in validated_data:
                setattr(instance, field, validated_data[field])
        instance.save(update_fields=[f for f in ("estado", "nivel", "is_active") if f in validated_data])
        return instance


class AdminUsuarioEditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Usuario
        fields = [
            "id",
            "username",
            "nombre",
            "apellido",
            "fecha_nacimiento",
            "email",
            "telefono",
            "estado",
            "nivel",
            "is_active",
        ]

    def validate_username(self, value):
        value = (value or "").strip()
        if not value:
            raise serializers.ValidationError("Usuario requerido.")
        qs = Usuario.objects.filter(username__iexact=value)
        if self.instance is not None:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("Ese usuario ya existe.")
        return value


class MeUsuarioSerializer(serializers.ModelSerializer):
    edad = serializers.SerializerMethodField()

    class Meta:
        model = Usuario
        fields = [
            "id",
            "username",
            "nombre",
            "apellido",
            "fecha_nacimiento",
            "edad",
            "email",
            "telefono",
            "estado",
        ]
        read_only_fields = [
            "estado",
            "edad",
        ]

    def get_edad(self, obj):
        return obj.edad

    def validate_username(self, value):
        value = (value or "").strip()
        if not value:
            raise serializers.ValidationError("Nombre de usuario requerido.")
        qs = Usuario.objects.filter(username__iexact=value)
        if self.instance is not None:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("Ese nombre de usuario ya existe.")
        return value

    def update(self, instance, validated_data):
        update_fields = []
        for f in ("username", "nombre", "apellido", "fecha_nacimiento", "email", "telefono"):
            if f in validated_data:
                setattr(instance, f, validated_data[f])
                update_fields.append(f)

        instance.save(update_fields=sorted(set(update_fields)))
        return instance
