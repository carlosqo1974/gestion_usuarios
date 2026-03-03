"""
Servidor Flask para la gestión de usuarios de Active Directory.
"""

from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from ldap_manager import ad, decode_logon_hours, encode_logon_hours, WEEKDAYS
from logger import get_logger, get_admin_logger
import config

log        = get_logger("app")
admin_log  = get_admin_logger()


def audit(accion: str, dn: str, ok: bool, detalle: str = ""):
    """Registra una acción administrativa en admin.log."""
    operador  = session.get("user", {}).get("username", "?")
    resultado = "OK" if ok else "ERROR"
    ip        = request.headers.get("X-Forwarded-For", request.remote_addr)
    linea     = f"{resultado}\t{operador}\t{ip}\t{accion}\t{dn}"
    if detalle:
        linea += f"\t{detalle}"
    admin_log.info(linea)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY


# ---------------------------------------------------------------------------
# Decorador de autenticación
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "No autenticado"}), 401
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def _user_has_group(user: dict, group_cn: str) -> bool:
    groups = [g.lower() for g in user.get("group_cns", [])]
    return group_cn.lower() in groups


def _compute_permissions(user: dict) -> dict:
    is_access_manager = _user_has_group(user, config.ACCESS_MANAGER_GROUP)
    in_supervisores = _user_has_group(user, config.PROFILE_GROUPS["supervisores"])
    in_gtr = _user_has_group(user, config.PROFILE_GROUPS["gtr"])

    can_change_password = in_supervisores or in_gtr or is_access_manager
    can_reset_account = in_supervisores or in_gtr or is_access_manager
    can_change_hours = in_gtr or is_access_manager

    return {
        "is_access_manager": is_access_manager,
        "can_change_password": can_change_password,
        "can_reset_account": can_reset_account,
        "can_change_hours": can_change_hours,
    }


def require_permission(permission_key: str):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = session.get("user")
            if not user:
                return jsonify({"ok": False, "error": "No autenticado"}), 401
            perms = user.get("permissions", {})
            if not perms.get(permission_key, False):
                return jsonify({"ok": False, "error": "No autorizado para esta operación"}), 403
            return f(*args, **kwargs)

        return decorated

    return decorator


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if not username or not password:
            error = "Introduce usuario y contraseña"
            log.warning("LOGIN sin datos — IP=%s", ip)
        else:
            log.info("LOGIN intento — usuario=%s  IP=%s", username, ip)
            ok, msg, user_info = ad.authenticate_user(
                username, password, config.ADMIN_GROUPS
            )
            if ok:
                user_info["permissions"] = _compute_permissions(user_info)
                session["user"] = user_info
                log.info("LOGIN OK — usuario=%s  IP=%s", username, ip)
                next_url = request.args.get("next") or url_for("index")
                return redirect(next_url)
            else:
                log.warning("LOGIN FALLO — usuario=%s  IP=%s  motivo=%s", username, ip, msg)
                error = msg

    return render_template("login.html", error=error, admin_groups=config.ADMIN_GROUPS)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Páginas
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    return render_template("index.html", user=session["user"], profile_groups=config.PROFILE_GROUPS)


# ---------------------------------------------------------------------------
# API: Estado de conexión
# ---------------------------------------------------------------------------
@app.route("/api/status")
@login_required
def api_status():
    ok, msg = ad.test_connection()
    return jsonify({"connected": ok, "message": msg})


# ---------------------------------------------------------------------------
# API: Árbol de OUs
# ---------------------------------------------------------------------------
@app.route("/api/tree")
@login_required
def api_tree():
    try:
        nodes = ad.get_ou_tree(config.AD_BASE_DN)
        return jsonify({"ok": True, "nodes": nodes})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API: Búsqueda de usuarios
# ---------------------------------------------------------------------------
@app.route("/api/search")
@login_required
def api_search():
    term = request.args.get("q", "").strip()
    if not term:
        return jsonify({"ok": False, "error": "Término de búsqueda vacío"}), 400
    try:
        users = ad.search_users(term, base_dn=config.AD_BASE_DN)
        # Eliminar la matriz de horarios del listado (se pide al abrir usuario)
        for u in users:
            u.pop("logon_hours_matrix", None)
        return jsonify({"ok": True, "users": users, "count": len(users)})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API: Detalle de usuario
# ---------------------------------------------------------------------------
@app.route("/api/user/<path:sam>")
@login_required
def api_user(sam):
    try:
        user = ad.get_user(sam)
        if user is None:
            return jsonify({"ok": False, "error": "Usuario no encontrado"}), 404
        return jsonify({"ok": True, "user": user})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API: Cambiar contraseña
# ---------------------------------------------------------------------------
@app.route("/api/user/password", methods=["POST"])
@login_required
@require_permission("can_change_password")
def api_change_password():
    data        = request.get_json(force=True)
    dn          = data.get("dn", "").strip()
    pwd         = data.get("password", "")
    must_change = data.get("must_change", True)
    if not dn or not pwd:
        return jsonify({"ok": False, "error": "Faltan parámetros"}), 400
    if len(pwd) < 7:
        return jsonify({"ok": False, "error": "La contraseña debe tener al menos 7 caracteres"}), 400
    try:
        ok, msg = ad.change_password(dn, pwd, must_change=must_change)
        detalle = msg + (" | forzar_cambio=sí" if must_change else " | forzar_cambio=no")
        audit("CAMBIO_CLAVE", dn, ok, detalle)
        return jsonify({"ok": ok, "message": msg})
    except Exception as exc:
        audit("CAMBIO_CLAVE", dn, False, str(exc))
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API: Actualizar horarios de inicio de sesión
# ---------------------------------------------------------------------------
@app.route("/api/user/logonhours", methods=["POST"])
@login_required
@require_permission("can_change_hours")
def api_set_logon_hours():
    data   = request.get_json(force=True)
    dn     = data.get("dn", "").strip()
    matrix = data.get("matrix")       # lista[7][24] de bools
    clear  = data.get("clear", False) # True = sin restricciones

    if not dn:
        return jsonify({"ok": False, "error": "Falta el DN del usuario"}), 400

    try:
        if clear:
            ok, msg = ad.clear_logon_hours(dn)
            audit("HORARIO_SIN_RESTRICCION", dn, ok, msg)
        else:
            if not matrix or len(matrix) != 7:
                return jsonify({"ok": False, "error": "Matriz de horarios inválida"}), 400
            ok, msg = ad.set_logon_hours(dn, matrix)
            audit("HORARIO_MODIFICADO", dn, ok, msg)
        return jsonify({"ok": ok, "message": msg})
    except Exception as exc:
        audit("HORARIO_MODIFICADO", dn, False, str(exc))
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API: Habilitar / deshabilitar usuario
# ---------------------------------------------------------------------------
@app.route("/api/user/enable", methods=["POST"])
@login_required
@require_permission("can_reset_account")
def api_enable():
    data   = request.get_json(force=True)
    dn     = data.get("dn", "").strip()
    enable = data.get("enable", True)
    if not dn:
        return jsonify({"ok": False, "error": "Falta el DN"}), 400
    accion = "HABILITAR_CUENTA" if enable else "DESHABILITAR_CUENTA"
    try:
        if enable:
            ok, msg = ad.enable_user(dn)
        else:
            ok, msg = ad.disable_user(dn)
        audit(accion, dn, ok, msg)
        return jsonify({"ok": ok, "message": msg})
    except Exception as exc:
        audit(accion, dn, False, str(exc))
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API: Desbloquear cuenta
# ---------------------------------------------------------------------------
@app.route("/api/user/unlock", methods=["POST"])
@login_required
@require_permission("can_reset_account")
def api_unlock():
    data = request.get_json(force=True)
    dn   = data.get("dn", "").strip()
    if not dn:
        return jsonify({"ok": False, "error": "Falta el DN"}), 400
    try:
        ok, msg = ad.unlock_user(dn)
        audit("DESBLOQUEAR_CUENTA", dn, ok, msg)
        return jsonify({"ok": ok, "message": msg})
    except Exception as exc:
        audit("DESBLOQUEAR_CUENTA", dn, False, str(exc))
        return jsonify({"ok": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# API: Gestión de acceso por perfiles (solo Administradores)
# ---------------------------------------------------------------------------
@app.route("/api/access/profiles", methods=["GET"])
@login_required
@require_permission("is_access_manager")
def api_access_profiles():
    payload = {}
    for profile, group_cn in config.PROFILE_GROUPS.items():
        ok, data = ad.list_group_members(group_cn)
        if not ok:
            return jsonify({"ok": False, "error": str(data)}), 500
        payload[profile] = {"group": group_cn, "members": data}
    return jsonify({"ok": True, "profiles": payload})


@app.route("/api/access/profiles/assign", methods=["POST"])
@login_required
@require_permission("is_access_manager")
def api_access_assign():
    data = request.get_json(force=True)
    profile = (data.get("profile") or "").strip().lower()
    sam = (data.get("sam") or "").strip()
    if profile not in config.PROFILE_GROUPS:
        return jsonify({"ok": False, "error": "Perfil inválido"}), 400
    if not sam:
        return jsonify({"ok": False, "error": "Falta sAMAccountName"}), 400

    user_dn = ad.get_user_dn_by_sam(sam)
    if not user_dn:
        return jsonify({"ok": False, "error": f"Usuario no encontrado: {sam}"}), 404

    group_cn = config.PROFILE_GROUPS[profile]
    ok, msg = ad.add_user_to_group(user_dn, group_cn)
    audit("PERFIL_ASIGNADO", user_dn, ok, f"perfil={profile} grupo={group_cn} msg={msg}")
    status = 200 if ok else 500
    return jsonify({"ok": ok, "message": msg}), status


@app.route("/api/access/profiles/remove", methods=["POST"])
@login_required
@require_permission("is_access_manager")
def api_access_remove():
    data = request.get_json(force=True)
    profile = (data.get("profile") or "").strip().lower()
    sam = (data.get("sam") or "").strip()
    if profile not in config.PROFILE_GROUPS:
        return jsonify({"ok": False, "error": "Perfil inválido"}), 400
    if not sam:
        return jsonify({"ok": False, "error": "Falta sAMAccountName"}), 400

    user_dn = ad.get_user_dn_by_sam(sam)
    if not user_dn:
        return jsonify({"ok": False, "error": f"Usuario no encontrado: {sam}"}), 404

    group_cn = config.PROFILE_GROUPS[profile]
    ok, msg = ad.remove_user_from_group(user_dn, group_cn)
    audit("PERFIL_REMOVIDO", user_dn, ok, f"perfil={profile} grupo={group_cn} msg={msg}")
    status = 200 if ok else 500
    return jsonify({"ok": ok, "message": msg}), status

# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG)
