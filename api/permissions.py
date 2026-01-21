from rest_framework.permissions import BasePermission


class IsAdminNivel0(BasePermission):
    """Permite acceso solo a usuarios con nivel 0 (admin)."""

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not user or not getattr(user, "is_authenticated", False):
            return False
        raw = getattr(user, "nivel", None)
        try:
            nivel = int(raw)
        except (TypeError, ValueError):
            nivel = 1
        return nivel == 0


class IsAdminStaff(BasePermission):
    """Permite acceso solo a admins (nivel==0)."""

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not user or not getattr(user, "is_authenticated", False):
            return False
        raw = getattr(user, "nivel", None)
        try:
            nivel = int(raw)
        except (TypeError, ValueError):
            nivel = 1
        return nivel == 0


class IsEstadoActivo(BasePermission):
    """Permite acceso solo a usuarios autenticados con estado=="activo"."""

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not user or not getattr(user, "is_authenticated", False):
            return False
        return (getattr(user, "estado", None) or "") == "activo"
