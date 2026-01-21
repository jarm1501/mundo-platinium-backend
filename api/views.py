"""Compat: re-export de endpoints desde `views_fase1`.

Este módulo existe porque `backend/api/urls.py` importa desde `api.views`.
Mantenerlo como un wrapper fino evita que se mezclen implementaciones legacy.
"""

from . import views_fase1 as _v

health = _v.health

register_request = _v.register_request
login = _v.login
me = _v.me
me_update = _v.me_update
me_change_password = _v.me_change_password
me_update_security = _v.me_update_security
me_delete_account = _v.me_delete_account

forgot_start = _v.forgot_start
forgot_answer1 = _v.forgot_answer1
forgot_answer2 = _v.forgot_answer2
reset_password = _v.reset_password

materiales_list = _v.materiales_list
materiales_export_csv = _v.materiales_export_csv
materiales_create = _v.materiales_create
materiales_update = _v.materiales_update
materiales_delete = _v.materiales_delete

materiales_usos_list = _v.materiales_usos_list
materiales_usos_export_csv = _v.materiales_usos_export_csv
materiales_usos_create = _v.materiales_usos_create
materiales_usos_detail = _v.materiales_usos_detail
materiales_usos_return = _v.materiales_usos_return
materiales_movimientos_list = _v.materiales_movimientos_list
materiales_movimientos_export_csv = _v.materiales_movimientos_export_csv

materiales_ventas_list = _v.materiales_ventas_list
materiales_ventas_export_csv = _v.materiales_ventas_export_csv
materiales_ventas_create = _v.materiales_ventas_create
materiales_ventas_detail = _v.materiales_ventas_detail

admin_pending_list = _v.admin_pending_list
admin_pending_approve = _v.admin_pending_approve
admin_pending_reject = _v.admin_pending_reject

admin_users_list = _v.admin_users_list
admin_users_create = _v.admin_users_create
admin_users_reset_password = _v.admin_users_reset_password
admin_users_generate_password = _v.admin_users_generate_password
admin_users_delete = _v.admin_users_delete
admin_users_update = _v.admin_users_update

admin_audit_list = _v.admin_audit_list

admin_ip_list = _v.admin_ip_list
admin_ip_ban = _v.admin_ip_ban
admin_ip_unban = _v.admin_ip_unban

support_contacts = _v.support_contacts

__all__ = [
    "health",
    "register_request",
    "login",
    "me",
    "me_update",
    "me_change_password",
    "me_update_security",
    "me_delete_account",
    "forgot_start",
    "forgot_answer1",
    "forgot_answer2",
    "reset_password",
    "materiales_list",
    "materiales_export_csv",
    "materiales_create",
    "materiales_update",
    "materiales_delete",
    "materiales_usos_list",
    "materiales_usos_export_csv",
    "materiales_usos_create",
    "materiales_usos_detail",
    "materiales_usos_return",
    "materiales_movimientos_list",
    "materiales_movimientos_export_csv",
    "materiales_ventas_list",
    "materiales_ventas_export_csv",
    "materiales_ventas_create",
    "materiales_ventas_detail",
    "admin_pending_list",
    "admin_pending_approve",
    "admin_pending_reject",
    "admin_users_list",
    "admin_users_create",
    "admin_users_reset_password",
    "admin_users_generate_password",
    "admin_users_delete",
    "admin_users_update",
    "admin_audit_list",
    "admin_ip_list",
    "admin_ip_ban",
    "admin_ip_unban",
    "support_contacts",
]
