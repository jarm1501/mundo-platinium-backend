from __future__ import annotations

from datetime import date

from django.db import models


class Usuario(models.Model):
    # NOTE: tabs en este repo han dado problemas con análisis/linters en Windows.
    # Normalizamos a 4 espacios en todo el archivo.

    ESTADO_CHOICES = [
        ("pendiente", "pendiente"),
        ("activo", "activo"),
        ("rechazado", "rechazado"),
        ("baneado", "baneado"),
    ]

    username = models.CharField(max_length=80, unique=True)
    password_hash = models.CharField(max_length=200)

    # Datos personales
    nombre = models.CharField(max_length=120)
    apellido = models.CharField(max_length=120)
    fecha_nacimiento = models.DateField()

    email = models.EmailField(blank=True, null=True)
    telefono = models.CharField(max_length=30, blank=True, null=True)

    # límites de edición (para "Mi cuenta")
    # (mantenemos fecha_nacimiento_change_count solo si se usa; actualmente no aplicamos límites)
    fecha_nacimiento_change_count = models.PositiveSmallIntegerField(default=0)

    # Flujo de aprobación
    estado = models.CharField(max_length=20, choices=ESTADO_CHOICES, default="pendiente")

    # Roles (0=admin)
    nivel = models.IntegerField(default=1)
    is_active = models.BooleanField(default=True)

    # Seguridad: preguntas + respuestas (hash)
    sec_q1 = models.CharField(max_length=200)
    sec_a1_hash = models.CharField(max_length=200)
    sec_q2 = models.CharField(max_length=200)
    sec_a2_hash = models.CharField(max_length=200)

    # IPs (cifradas) - solo se muestran a admin
    signup_ip_hash = models.CharField(max_length=64, blank=True, null=True)
    signup_ip_enc = models.TextField(blank=True, null=True)
    last_login_ip_hash = models.CharField(max_length=64, blank=True, null=True)
    last_login_ip_enc = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def edad(self):
        if not self.fecha_nacimiento:
            return None
        today = date.today()
        years = today.year - self.fecha_nacimiento.year
        if (today.month, today.day) < (self.fecha_nacimiento.month, self.fecha_nacimiento.day):
            years -= 1
        return max(years, 0)

    @property
    def is_admin(self):
        try:
            return int(self.nivel) == 0
        except Exception:
            return False

    def __str__(self):
        return f"{self.username} ({self.estado}, nivel {self.nivel})"


class Material(models.Model):
    nombre = models.CharField(max_length=200)
    tipo = models.CharField(max_length=120, blank=True, default="")
    unidad = models.CharField(max_length=40, blank=True, default="unidad")
    # precio = costo unitario (lo que costó adquirirlo)
    precio = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    # vendible = se registra como producto de venta (no es POS; solo control interno)
    vendible = models.BooleanField(default=False)
    # precio_venta = precio unitario de referencia para estimar ingresos
    precio_venta = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    ubicacion = models.CharField(max_length=200, blank=True, default="")
    # cantidad = disponible en almacén
    cantidad = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    # en_uso = prestado / en obra / en proceso (no disponible)
    en_uso = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    minimo = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    propio = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["nombre"]),
            models.Index(fields=["tipo"]),
            models.Index(fields=["precio"]),
        ]

    def __str__(self):
        return self.nombre


class MaterialUso(models.Model):
    class Estado(models.TextChoices):
        ABIERTO = "abierto", "abierto"
        CERRADO = "cerrado", "cerrado"
        CANCELADO = "cancelado", "cancelado"

    created_at = models.DateTimeField(auto_now_add=True)
    closed_at = models.DateTimeField(blank=True, null=True)

    creado_por = models.ForeignKey(Usuario, on_delete=models.SET_NULL, null=True, blank=True, related_name="usos_creados")
    responsable = models.CharField(max_length=120, blank=True, default="")
    destino = models.CharField(max_length=200, blank=True, default="")
    notas = models.TextField(blank=True, default="")
    estado = models.CharField(max_length=20, choices=Estado.choices, default=Estado.ABIERTO)

    class Meta:
        indexes = [models.Index(fields=["created_at"]), models.Index(fields=["estado"])]

    def __str__(self):
        return f"Uso #{self.id} ({self.estado})"


class MaterialUsoItem(models.Model):
    uso = models.ForeignKey(MaterialUso, on_delete=models.CASCADE, related_name="items")
    material = models.ForeignKey(Material, on_delete=models.PROTECT, related_name="uso_items")

    cantidad_salida = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    cantidad_devuelta = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    cantidad_consumida = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    cantidad_rota = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    cantidad_perdida = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    class Meta:
        indexes = [models.Index(fields=["uso"]), models.Index(fields=["material"]) ]

    def __str__(self):
        return f"UsoItem({self.material_id})"


class MaterialMovimiento(models.Model):
    class Tipo(models.TextChoices):
        SALIDA = "salida", "salida"
        DEVOLUCION = "devolucion", "devolucion"
        CONSUMO = "consumo", "consumo"
        ROTO = "roto", "roto"
        PERDIDO = "perdido", "perdido"
        VENTA = "venta", "venta"
        AJUSTE = "ajuste", "ajuste"

    ts = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=80, blank=True, default="")
    tipo = models.CharField(max_length=20, choices=Tipo.choices)

    material = models.ForeignKey(Material, on_delete=models.PROTECT, related_name="movimientos")
    uso = models.ForeignKey(MaterialUso, on_delete=models.SET_NULL, null=True, blank=True, related_name="movimientos")

    cantidad = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    nota = models.CharField(max_length=240, blank=True, default="")

    class Meta:
        indexes = [models.Index(fields=["ts"]), models.Index(fields=["material"]), models.Index(fields=["tipo"])]

    def __str__(self):
        return f"{self.ts} {self.tipo} {self.material_id} {self.cantidad}"


class MaterialVenta(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    creado_por = models.ForeignKey(Usuario, on_delete=models.SET_NULL, null=True, blank=True, related_name="ventas_creadas")
    notas = models.TextField(blank=True, default="")

    class Meta:
        indexes = [models.Index(fields=["created_at"])]

    def __str__(self):
        return f"Venta #{self.id}"


class MaterialVentaItem(models.Model):
    venta = models.ForeignKey(MaterialVenta, on_delete=models.CASCADE, related_name="items")
    material = models.ForeignKey(Material, on_delete=models.PROTECT, related_name="venta_items")

    cantidad = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    # Snapshots para reportes consistentes aunque cambien precios luego
    costo_unitario = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    precio_venta_unitario = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    class Meta:
        indexes = [models.Index(fields=["venta"]), models.Index(fields=["material"]) ]

    def __str__(self):
        return f"VentaItem({self.material_id})"


class AuditLog(models.Model):
    ts = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=80, blank=True, default="")
    actor_id = models.BigIntegerField(null=True, blank=True)
    action = models.CharField(max_length=40)
    entity = models.CharField(max_length=80)
    entity_id = models.IntegerField(null=True, blank=True)
    before_json = models.TextField(null=True, blank=True)
    after_json = models.TextField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["ts"])]

    def __str__(self):
        return f"{self.ts} {self.actor} {self.action} {self.entity}#{self.entity_id}"


class IpRecord(models.Model):
    class Estado(models.TextChoices):
        OK = "ok", "ok"
        COOLDOWN = "cooldown", "cooldown"
        BANNED = "banned", "banned"

    ip_hash = models.CharField(max_length=64, unique=True)
    ip_enc = models.TextField()

    estado = models.CharField(max_length=20, choices=Estado.choices, default=Estado.OK)
    cooldown_until = models.DateTimeField(blank=True, null=True)

    # Login policy
    login_stage = models.IntegerField(default=0)  # 0=primera ronda, 1=segunda ronda
    login_fails = models.IntegerField(default=0)

    # Forgot policy
    forgot_round = models.IntegerField(default=0)  # 0=primera ronda, 1=segunda ronda
    forgot_step = models.IntegerField(default=1)  # 1=pregunta1, 2=pregunta2
    forgot_fail1 = models.IntegerField(default=0)
    forgot_fail2 = models.IntegerField(default=0)

    geo_country = models.CharField(max_length=40, blank=True, null=True)
    geo_region = models.CharField(max_length=80, blank=True, null=True)

    last_seen = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"IpRecord({self.estado})"
