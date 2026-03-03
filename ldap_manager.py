"""
Módulo de gestión de usuarios en Active Directory via LDAP.
Soporta: búsqueda, lectura de atributos, cambio de contraseña y modificación de horarios.
"""

import struct
from datetime import datetime, timezone, timedelta
from ldap3 import (
    Server, Connection, ALL, NTLM, SUBTREE, MODIFY_REPLACE,
    MODIFY_DELETE, MODIFY_ADD, Tls, AUTO_BIND_TLS_BEFORE_BIND
)
from ldap3.core.exceptions import LDAPException
import config
from logger import get_logger

log = get_logger("ldap")

# Atributos AD que se recuperan por usuario
USER_ATTRS = [
    "sAMAccountName", "displayName", "cn", "mail", "department",
    "title", "telephoneNumber", "userAccountControl", "logonHours",
    "lastLogon", "lastLogonTimestamp", "pwdLastSet", "badPwdCount",
    "badPasswordTime", "lockoutTime", "distinguishedName", "memberOf",
    "description", "whenCreated", "whenChanged",
]

# Flags de userAccountControl
UAC_DISABLED        = 0x0002
UAC_PASSWORD_NEVER  = 0x10000
UAC_PASSWORD_NOEXP  = 0x10000

# Días de la semana en AD (UTC, empieza en domingo)
WEEKDAYS = ["Dom", "Lun", "Mar", "Mié", "Jue", "Vie", "Sáb"]


# ---------------------------------------------------------------------------
# Conversión de tiempo Windows FILETIME → datetime
# ---------------------------------------------------------------------------
def _filetime_to_dt(filetime: int) -> datetime | None:
    if filetime in (0, 9223372036854775807):
        return None
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return epoch + timedelta(microseconds=filetime // 10)


def _dt_to_str(dt: datetime | None) -> str:
    if dt is None:
        return "Nunca"
    return dt.strftime("%d/%m/%Y %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# Codificación/decodificación de logonHours
# ---------------------------------------------------------------------------
def decode_logon_hours(raw: bytes, tz_offset: int = 0) -> list[list[bool]]:
    """
    Decodifica 21 bytes de logonHours en una matriz [día][hora] (bool).
    tz_offset: desplazamiento de UTC en horas para mostrar hora local.
    Devuelve matriz[7][24] donde [0] = Domingo, [1] = Lunes, …
    """
    if raw is None:
        # Sin restricción → todo permitido
        return [[True] * 24 for _ in range(7)]

    if len(raw) != 21:
        return [[True] * 24 for _ in range(7)]

    # Convertir bytes a array de bits (168 bits, LSB primero por byte)
    bits: list[bool] = []
    for byte in raw:
        for bit in range(8):
            bits.append(bool(byte & (1 << bit)))

    # bits[i] → hora i de la semana en UTC (i=0 = domingo 00:00 UTC)
    matrix = [[False] * 24 for _ in range(7)]
    for i, allowed in enumerate(bits):
        day  = i // 24
        hour = i % 24
        matrix[day][hour] = allowed

    # Aplicar desplazamiento de zona horaria
    if tz_offset != 0:
        matrix = _shift_logon_hours(matrix, tz_offset)

    return matrix


def encode_logon_hours(matrix: list[list[bool]], tz_offset: int = 0) -> bytes:
    """
    Codifica una matriz [7][24] de bools en 21 bytes para AD.
    Convierte de hora local a UTC antes de codificar.
    """
    if tz_offset != 0:
        matrix = _shift_logon_hours(matrix, -tz_offset)

    bits = []
    for day in matrix:
        for allowed in day:
            bits.append(allowed)

    raw = bytearray(21)
    for i, allowed in enumerate(bits):
        if allowed:
            raw[i // 8] |= (1 << (i % 8))

    return bytes(raw)


def _shift_logon_hours(matrix: list[list[bool]], hours: int) -> list[list[bool]]:
    """Desplaza la matriz de horarios en 'hours' horas (puede ser negativo)."""
    flat = [matrix[d][h] for d in range(7) for h in range(24)]
    total = len(flat)
    shift = hours % total
    flat = flat[shift:] + flat[:shift]
    new_matrix = []
    for d in range(7):
        new_matrix.append(flat[d * 24:(d + 1) * 24])
    return new_matrix


def all_hours_allowed(matrix: list[list[bool]]) -> bool:
    return all(h for day in matrix for h in day)


# ---------------------------------------------------------------------------
# Clase principal de conexión AD
# ---------------------------------------------------------------------------
class ADManager:
    def __init__(self):
        self._conn: Connection | None = None

    def _build_server(self) -> Server:
        tls_config = Tls(
            validate=config.TLS_VALIDATE_MODE,
            ca_certs_file=config.AD_CA_CERT_FILE or None,
            version=config.TLS_VERSION,
            valid_names=config.AD_TLS_VALID_NAMES or None,
        )
        return Server(
            config.AD_SERVER,
            port=config.AD_PORT,
            use_ssl=config.AD_USE_SSL,
            tls=tls_config,
            get_info=ALL,
        )

    def _is_secure_connection(self, conn: Connection) -> bool:
        return bool(conn.server.ssl or getattr(conn, "tls_started", False))

    def _extract_group_cns(self, member_of: list) -> list[str]:
        cns: list[str] = []
        for g in member_of or []:
            dn = str(g)
            first = dn.split(",", 1)[0]
            if first.upper().startswith("CN="):
                cns.append(first[3:])
        return cns

    def _friendly_ldap_error(self, exc: Exception) -> str:
        msg = str(exc)
        cert_error_hints = (
            "CERTIFICATE_VERIFY_FAILED",
            "unable to get local issuer certificate",
            "self signed certificate",
        )
        if any(h in msg for h in cert_error_hints):
            return (
                f"{msg}. Verifica la cadena de certificados del DC. "
                "Opciones: configurar AD_CA_CERT_FILE con la CA corporativa, "
                "instalar la CA en el trust store del sistema, o (solo temporalmente) "
                "usar AD_TLS_VALIDATE=none."
            )
        if "doesn't match any name in" in msg:
            return (
                f"{msg}. El certificado del DC es válido pero el nombre no coincide. "
                "Usa AD_SERVER con FQDN del DC (ej. DC01.contact.com) en lugar de IP, "
                "o configura AD_TLS_VALID_NAMES con el/los nombres DNS permitidos del certificado."
            )
        return msg

    # ------------------------------------------------------------------
    def connect(self) -> tuple[bool, str]:
        log.debug("Conectando al AD: server=%s  port=%s  ssl=%s  bind_dn=%s",
                  config.AD_SERVER, config.AD_PORT, config.AD_USE_SSL, config.AD_BIND_DN)
        try:
            server = self._build_server()
            self._conn = Connection(
                server,
                user=config.AD_BIND_DN,
                password=config.AD_PASSWORD,
                auto_bind=AUTO_BIND_TLS_BEFORE_BIND if (not config.AD_USE_SSL and config.AD_START_TLS) else True,
            )
            if config.AD_START_TLS and not config.AD_USE_SSL and not self._conn.tls_started:
                self._conn.start_tls()
            log.info("Conexión admin establecida con %s", config.AD_SERVER)
            return True, "Conexión establecida"
        except LDAPException as exc:
            log.error("Error al conectar con el AD: %s", exc)
            return False, self._friendly_ldap_error(exc)

    @property
    def conn(self) -> Connection:
        if self._conn is None or not self._conn.bound:
            ok, msg = self.connect()
            if not ok:
                raise RuntimeError(f"No se pudo conectar al AD: {msg}")
        return self._conn

    def disconnect(self):
        if self._conn:
            self._conn.unbind()
            self._conn = None

    # ------------------------------------------------------------------
    def test_connection(self) -> tuple[bool, str]:
        try:
            ok, msg = self.connect()
            if ok:
                self.disconnect()
            return ok, msg
        except Exception as exc:
            return False, str(exc)

    # ------------------------------------------------------------------
    def authenticate_user(
        self, username: str, password: str, required_groups: list[str]
    ) -> tuple[bool, str, dict | None]:
        """
        Verifica credenciales contra AD y comprueba membresía en al menos uno de required_groups.
        Devuelve (ok, mensaje, user_info | None).
        """
        log.info("Intento de autenticación — usuario: %s  grupos_requeridos: %s", username, required_groups)

        # 1. Intentar bind con las credenciales del usuario
        # Probamos UPN (usuario@dominio) primero, luego NetBIOS (DOMINIO\usuario)
        candidates = [
            f"{username}@{config.AD_DOMAIN}",
            f"{config.AD_DOMAIN}\\{username}",
        ]

        server = self._build_server()

        bind_ok = False
        last_exc = None
        for bind_user in candidates:
            log.debug("Paso 1: probando bind — %s  servidor: %s:%s  ssl=%s",
                      bind_user, config.AD_SERVER, config.AD_PORT, config.AD_USE_SSL)
            try:
                user_conn = Connection(
                    server,
                    user=bind_user,
                    password=password,
                    auto_bind=AUTO_BIND_TLS_BEFORE_BIND if (not config.AD_USE_SSL and config.AD_START_TLS) else True,
                )
                if config.AD_START_TLS and not config.AD_USE_SSL and not user_conn.tls_started:
                    user_conn.start_tls()
                user_conn.unbind()
                log.debug("Paso 1: bind correcto con formato '%s'", bind_user)
                bind_ok = True
                break
            except LDAPException as exc:
                log.warning("Paso 1: formato '%s' rechazado — %s", bind_user, self._friendly_ldap_error(exc))
                last_exc = exc

        if not bind_ok:
            log.warning("Paso 1 FALLO — ningún formato funcionó para '%s'", username)
            return False, "Usuario o contraseña incorrectos", None

        # 2. Buscar el usuario con la conexión admin y verificar el grupo
        ldap_filter = (
            f"(&(objectClass=user)(objectCategory=person)"
            f"(sAMAccountName={username}))"
        )
        log.debug("Paso 2: buscando usuario en base=%s  filtro=%s", config.AD_AUTH_BASE, ldap_filter)
        self.conn.search(
            config.AD_AUTH_BASE,
            ldap_filter,
            attributes=["displayName", "memberOf", "distinguishedName", "mail",
                        "userAccountControl"],
        )

        if not self.conn.entries:
            log.warning("Paso 2 FALLO — usuario '%s' no encontrado en base='%s'",
                        username, config.AD_AUTH_BASE)
            return False, "Usuario no encontrado en el directorio permitido", None

        entry = self.conn.entries[0]
        log.debug("Paso 2: usuario encontrado — DN=%s", entry.distinguishedName)

        # Verificar cuenta habilitada
        uac = int(entry.userAccountControl.value) if entry.userAccountControl else 0
        if uac & UAC_DISABLED:
            log.warning("Paso 3 FALLO — cuenta deshabilitada para %s (UAC=%s)", username, uac)
            return False, "La cuenta está deshabilitada", None

        # Verificar membresía (compara CN del grupo, sin distinguir mayúsculas)
        member_of = entry.memberOf.values if entry.memberOf else []
        log.debug("Paso 3: grupos del usuario %s: %s", username,
                  [str(g) for g in member_of] if member_of else "(ninguno)")

        required_groups = [g for g in required_groups if g]
        in_allowed_group = any(
            any(str(g).lower().startswith(f"cn={required.lower()},") for g in member_of)
            for required in required_groups
        )
        if not in_allowed_group:
            log.warning("Paso 3 FALLO — %s no pertenece a los grupos permitidos %s. Grupos actuales: %s",
                        username, required_groups, [str(g) for g in member_of])
            grupos_txt = ", ".join(required_groups) if required_groups else "(sin grupos configurados)"
            return False, f"Acceso denegado: se requiere pertenecer a uno de estos grupos: {grupos_txt}", None

        group_cns = self._extract_group_cns(member_of)
        user_info = {
            "username": username,
            "displayName": str(entry.displayName) if entry.displayName else username,
            "mail": str(entry.mail) if entry.mail else "",
            "dn": str(entry.distinguishedName),
            "group_cns": group_cns,
        }
        log.info("Autenticación CORRECTA — %s (%s)", username, user_info["displayName"])
        return True, "Autenticación correcta", user_info

    # ------------------------------------------------------------------
    def search_users(self, search_term: str, base_dn: str | None = None) -> list[dict]:
        """Busca usuarios por nombre, cuenta o correo."""
        base = base_dn or config.AD_BASE_DN
        if not search_term.strip():
            return []

        t = search_term.replace("(", "\\28").replace(")", "\\29").replace("*", "\\2a")
        ldap_filter = (
            f"(&(objectClass=user)(objectCategory=person)"
            f"(|(sAMAccountName=*{t}*)(displayName=*{t}*)"
            f"(cn=*{t}*)(mail=*{t}*)(givenName=*{t}*)(sn=*{t}*)))"
        )

        self.conn.search(base, ldap_filter, search_scope=SUBTREE, attributes=USER_ATTRS)
        return [self._entry_to_dict(e) for e in self.conn.entries]

    # ------------------------------------------------------------------
    def get_user(self, sam_account: str) -> dict | None:
        """Obtiene un usuario por sAMAccountName."""
        ldap_filter = (
            f"(&(objectClass=user)(objectCategory=person)"
            f"(sAMAccountName={sam_account}))"
        )
        self.conn.search(
            config.AD_BASE_DN, ldap_filter,
            search_scope=SUBTREE, attributes=USER_ATTRS
        )
        if not self.conn.entries:
            return None
        return self._entry_to_dict(self.conn.entries[0])

    # ------------------------------------------------------------------
    def get_ou_tree(self, base_dn: str | None = None) -> list[dict]:
        """Devuelve el árbol de OUs para el navegador."""
        base = base_dn or config.AD_BASE_DN
        self.conn.search(
            base,
            "(|(objectClass=organizationalUnit)(objectClass=container))",
            search_scope=SUBTREE,
            attributes=["ou", "cn", "distinguishedName"],
        )
        nodes = []
        for e in self.conn.entries:
            dn = str(e.distinguishedName)
            name = (
                str(e.ou) if e.ou else str(e.cn) if e.cn else dn.split(",")[0]
            )
            nodes.append({"dn": dn, "name": name})
        return sorted(nodes, key=lambda x: x["dn"])

    # ------------------------------------------------------------------
    def change_password(self, dn: str, new_password: str, must_change: bool = True) -> tuple[bool, str]:
        """Cambia la contraseña de un usuario (requiere privilegios admin).
        must_change=True pone pwdLastSet=0 para forzar cambio en el próximo logon.
        """
        if config.AD_REQUIRE_SECURE_PASSWORD_OPS and not self._is_secure_connection(self.conn):
            return False, (
                "Operación rechazada: el cambio de contraseña requiere LDAPS o StartTLS "
                "(AD_USE_SSL=true o AD_START_TLS=true)."
            )

        encoded = f'"{new_password}"'.encode("utf-16-le")
        changes = {"unicodePwd": [(MODIFY_REPLACE, [encoded])]}
        if must_change:
            # pwdLastSet=0 → AD exige cambio en el siguiente inicio de sesión
            changes["pwdLastSet"] = [(MODIFY_REPLACE, [0])]
        try:
            result = self.conn.modify(dn, changes)
            if result:
                suffix = " (se solicitará cambio en el próximo logon)" if must_change else ""
                return True, f"Contraseña cambiada correctamente{suffix}"
            return False, str(self.conn.result)
        except LDAPException as exc:
            return False, str(exc)

    # ------------------------------------------------------------------
    def set_logon_hours(
        self, dn: str, matrix: list[list[bool]]
    ) -> tuple[bool, str]:
        """Establece los horarios de inicio de sesión."""
        raw = encode_logon_hours(matrix, config.TIMEZONE_OFFSET)
        try:
            result = self.conn.modify(
                dn,
                {"logonHours": [(MODIFY_REPLACE, [raw])]},
            )
            if result:
                return True, "Horarios actualizados correctamente"
            return False, str(self.conn.result)
        except LDAPException as exc:
            return False, str(exc)

    # ------------------------------------------------------------------
    def clear_logon_hours(self, dn: str) -> tuple[bool, str]:
        """Elimina restricciones de horario (acceso 24/7)."""
        all_on = bytes([0xFF] * 21)
        try:
            result = self.conn.modify(
                dn,
                {"logonHours": [(MODIFY_REPLACE, [all_on])]},
            )
            if result:
                return True, "Restricciones de horario eliminadas"
            return False, str(self.conn.result)
        except LDAPException as exc:
            return False, str(exc)

    # ------------------------------------------------------------------
    def enable_user(self, dn: str) -> tuple[bool, str]:
        return self._toggle_uac(dn, enable=True)

    def disable_user(self, dn: str) -> tuple[bool, str]:
        return self._toggle_uac(dn, enable=False)

    def _toggle_uac(self, dn: str, enable: bool) -> tuple[bool, str]:
        self.conn.search(
            config.AD_BASE_DN,
            f"(distinguishedName={dn})",
            attributes=["userAccountControl"],
        )
        if not self.conn.entries:
            return False, "Usuario no encontrado"

        uac = int(self.conn.entries[0].userAccountControl.value)
        if enable:
            new_uac = uac & ~UAC_DISABLED
            action = "habilitado"
        else:
            new_uac = uac | UAC_DISABLED
            action = "deshabilitado"

        try:
            result = self.conn.modify(
                dn,
                {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]},
            )
            if result:
                return True, f"Usuario {action} correctamente"
            return False, str(self.conn.result)
        except LDAPException as exc:
            return False, str(exc)

    # ------------------------------------------------------------------
    def unlock_user(self, dn: str) -> tuple[bool, str]:
        """Desbloquea una cuenta bloqueada."""
        try:
            result = self.conn.modify(
                dn,
                {"lockoutTime": [(MODIFY_REPLACE, [0])]},
            )
            if result:
                return True, "Cuenta desbloqueada correctamente"
            return False, str(self.conn.result)
        except LDAPException as exc:
            return False, str(exc)

    # ------------------------------------------------------------------
    def get_user_dn_by_sam(self, sam: str) -> str | None:
        self.conn.search(
            config.AD_BASE_DN,
            f"(&(objectClass=user)(objectCategory=person)(sAMAccountName={sam}))",
            attributes=["distinguishedName"],
        )
        if not self.conn.entries:
            return None
        return str(self.conn.entries[0].distinguishedName)

    def get_group_dn_by_cn(self, cn: str) -> str | None:
        self.conn.search(
            config.AD_BASE_DN,
            f"(&(objectClass=group)(cn={cn}))",
            attributes=["distinguishedName"],
        )
        if not self.conn.entries:
            return None
        return str(self.conn.entries[0].distinguishedName)

    def add_user_to_group(self, user_dn: str, group_cn: str) -> tuple[bool, str]:
        group_dn = self.get_group_dn_by_cn(group_cn)
        if not group_dn:
            return False, f"Grupo no encontrado: {group_cn}"
        try:
            ok = self.conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
            if ok:
                return True, f"Usuario agregado a {group_cn}"
            result = str(self.conn.result)
            if "entryAlreadyExists" in result:
                return True, f"El usuario ya pertenece a {group_cn}"
            return False, result
        except LDAPException as exc:
            return False, str(exc)

    def remove_user_from_group(self, user_dn: str, group_cn: str) -> tuple[bool, str]:
        group_dn = self.get_group_dn_by_cn(group_cn)
        if not group_dn:
            return False, f"Grupo no encontrado: {group_cn}"
        try:
            ok = self.conn.modify(group_dn, {"member": [(MODIFY_DELETE, [user_dn])]})
            if ok:
                return True, f"Usuario removido de {group_cn}"
            result = str(self.conn.result)
            if "noSuchAttribute" in result:
                return True, f"El usuario no pertenecía a {group_cn}"
            return False, result
        except LDAPException as exc:
            return False, str(exc)

    def list_group_members(self, group_cn: str) -> tuple[bool, list[dict] | str]:
        group_dn = self.get_group_dn_by_cn(group_cn)
        if not group_dn:
            return False, f"Grupo no encontrado: {group_cn}"
        self.conn.search(group_dn, "(objectClass=group)", attributes=["member"])
        if not self.conn.entries:
            return False, f"Grupo no encontrado: {group_cn}"
        members = self.conn.entries[0].member.values if self.conn.entries[0].member else []
        out = []
        for member_dn in members:
            self.conn.search(str(member_dn), "(objectClass=user)", attributes=["sAMAccountName", "displayName", "distinguishedName"])
            if not self.conn.entries:
                continue
            e = self.conn.entries[0]
            out.append({
                "sAMAccountName": str(e.sAMAccountName) if e.sAMAccountName else "",
                "displayName": str(e.displayName) if e.displayName else "",
                "distinguishedName": str(e.distinguishedName) if e.distinguishedName else str(member_dn),
            })
        out.sort(key=lambda x: (x.get("displayName") or x.get("sAMAccountName") or "").lower())
        return True, out

    # ------------------------------------------------------------------
    def _entry_to_dict(self, entry) -> dict:
        """Convierte una entrada LDAP en un diccionario serializable."""
        def _val(attr):
            try:
                v = getattr(entry, attr)
                if not v:
                    return None
                raw = v.raw_values
                val = v.value
                if attr == "logonHours":
                    return raw[0].hex() if raw else None
                if attr in ("lastLogon", "lastLogonTimestamp", "pwdLastSet",
                            "badPasswordTime", "lockoutTime"):
                    try:
                        return _dt_to_str(_filetime_to_dt(int(val)))
                    except Exception:
                        return str(val)
                if attr == "memberOf":
                    if isinstance(val, list):
                        return val
                    return [str(val)]
                if attr == "userAccountControl":
                    return int(val)
                return str(val) if val else None
            except Exception:
                return None

        d = {a: _val(a) for a in USER_ATTRS}
        uac = d.get("userAccountControl") or 0
        d["enabled"] = not bool(uac & UAC_DISABLED)
        d["password_never_expires"] = bool(uac & UAC_PASSWORD_NEVER)

        # Decodificar horarios para el frontend
        raw_hex = d.get("logonHours")
        if raw_hex:
            raw_bytes = bytes.fromhex(raw_hex)
            matrix = decode_logon_hours(raw_bytes, config.TIMEZONE_OFFSET)
            d["logon_hours_matrix"] = matrix
            d["logon_hours_unrestricted"] = all_hours_allowed(matrix)
        else:
            d["logon_hours_matrix"] = [[True] * 24 for _ in range(7)]
            d["logon_hours_unrestricted"] = True

        return d


# Instancia global reutilizable
ad = ADManager()
