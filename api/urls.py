from django.urls import path

from . import views

urlpatterns = [
    path("health/", views.health),

    path("auth/register_request/", views.register_request),
    path("auth/login/", views.login),
    path("auth/me/", views.me),
    path("auth/me/update/", views.me_update),
    path("auth/me/change_password/", views.me_change_password),
    path("auth/me/security/", views.me_update_security),
    path("auth/me/delete/", views.me_delete_account),

    path("auth/forgot/start/", views.forgot_start),
    path("auth/forgot/answer1/", views.forgot_answer1),
    path("auth/forgot/answer2/", views.forgot_answer2),
    path("auth/forgot/reset/", views.reset_password),

    path("materiales/", views.materiales_list),
    path("materiales/export.csv", views.materiales_export_csv),
    path("materiales/crear/", views.materiales_create),
    path("materiales/<int:mat_id>/", views.materiales_update),
    path("materiales/<int:mat_id>/eliminar/", views.materiales_delete),

    path("materiales/usos/", views.materiales_usos_list),
    path("materiales/usos/export.csv", views.materiales_usos_export_csv),
    path("materiales/usos/crear/", views.materiales_usos_create),
    path("materiales/usos/<int:uso_id>/", views.materiales_usos_detail),
    path("materiales/usos/<int:uso_id>/devolver/", views.materiales_usos_return),
    path("materiales/movimientos/", views.materiales_movimientos_list),
    path("materiales/movimientos/export.csv", views.materiales_movimientos_export_csv),
    path("materiales/ventas/", views.materiales_ventas_list),
    path("materiales/ventas/export.csv", views.materiales_ventas_export_csv),
    path("materiales/ventas/crear/", views.materiales_ventas_create),
    path("materiales/ventas/<int:venta_id>/", views.materiales_ventas_detail),

    path("admin/solicitudes/", views.admin_pending_list),
    path("admin/solicitudes/<int:user_id>/aprobar/", views.admin_pending_approve),
    path("admin/solicitudes/<int:user_id>/rechazar/", views.admin_pending_reject),

    path("admin/usuarios/", views.admin_users_list),
    path("admin/usuarios/crear/", views.admin_users_create),
    path("admin/usuarios/<int:user_id>/reset_password/", views.admin_users_reset_password),
    path("admin/usuarios/<int:user_id>/generar_clave/", views.admin_users_generate_password),
    path("admin/usuarios/<int:user_id>/eliminar/", views.admin_users_delete),
    path("admin/usuarios/<int:user_id>/actualizar/", views.admin_users_update),
    path("admin/auditoria/", views.admin_audit_list),

    path("admin/ip/", views.admin_ip_list),
    path("admin/ip/ban/", views.admin_ip_ban),
    path("admin/ip/unban/", views.admin_ip_unban),

    # Soporte (solo lectura)
    path("support/contacts/", views.support_contacts),
]
