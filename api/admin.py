from django.contrib import admin

from .models import AuditLog, IpRecord, Material, Usuario


@admin.register(Usuario)
class UsuarioAdmin(admin.ModelAdmin):
    list_display = ("username", "estado", "nivel", "is_active", "created_at")
    search_fields = ("username", "nombre", "apellido", "email")
    list_filter = ("estado", "nivel", "is_active")


@admin.register(Material)
class MaterialAdmin(admin.ModelAdmin):
    list_display = ("nombre", "tipo", "precio", "cantidad", "minimo", "propio", "updated_at")
    search_fields = ("nombre", "tipo", "ubicacion")
    list_filter = ("propio",)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("ts", "actor", "action", "entity", "entity_id")
    search_fields = ("actor", "action", "entity")
    list_filter = ("action", "entity")


@admin.register(IpRecord)
class IpRecordAdmin(admin.ModelAdmin):
    list_display = ("estado", "geo_country", "geo_region", "last_seen", "created_at")
    list_filter = ("estado", "geo_country")
