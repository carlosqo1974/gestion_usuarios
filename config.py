import os
import ssl
from dotenv import load_dotenv

load_dotenv()

# Active Directory connection
AD_SERVER   = os.getenv("AD_SERVER", "your-dc.domain.local")
AD_DOMAIN   = os.getenv("AD_DOMAIN", "DOMAIN")
AD_BASE_DN  = os.getenv("AD_BASE_DN", "DC=domain,DC=local")
AD_BIND_DN  = os.getenv("AD_BIND_DN", "CN=admin,CN=Users,DC=domain,DC=local")
AD_PASSWORD = os.getenv("AD_PASSWORD", "")
AD_USE_SSL  = os.getenv("AD_USE_SSL", "false").lower() == "true"
AD_START_TLS = os.getenv("AD_START_TLS", "true").lower() == "true"
AD_PORT     = int(os.getenv("AD_PORT", 636 if AD_USE_SSL else 389))

# TLS/LDAPS hardening
AD_TLS_VALIDATE = os.getenv("AD_TLS_VALIDATE", "required").strip().lower()
AD_CA_CERT_FILE = os.getenv("AD_CA_CERT_FILE", "")
AD_TLS_VERSION = os.getenv("AD_TLS_VERSION", "TLSv1_2")
AD_REQUIRE_SECURE_PASSWORD_OPS = os.getenv("AD_REQUIRE_SECURE_PASSWORD_OPS", "true").lower() == "true"
AD_TLS_VALID_NAMES = [n.strip() for n in os.getenv("AD_TLS_VALID_NAMES", "").split(",") if n.strip()]

TLS_VALIDATE_MAP = {
    "required": ssl.CERT_REQUIRED,
    "none": ssl.CERT_NONE,
    "optional": ssl.CERT_OPTIONAL,
}
TLS_VALIDATE_MODE = TLS_VALIDATE_MAP.get(AD_TLS_VALIDATE, ssl.CERT_REQUIRED)
TLS_VERSION_MAP = {
    "TLSv1_2": ssl.PROTOCOL_TLSv1_2,
    "TLSv1": ssl.PROTOCOL_TLSv1,
    "TLS": ssl.PROTOCOL_TLS,
}
TLS_VERSION = TLS_VERSION_MAP.get(AD_TLS_VERSION, ssl.PROTOCOL_TLSv1_2)

# Permite AD_SERVER con o sin esquema
for prefix in ("ldap://", "ldaps://"):
    if AD_SERVER.lower().startswith(prefix):
        AD_SERVER = AD_SERVER[len(prefix):]
        break

# Base para buscar al usuario que hace LOGIN (todo el dominio por defecto).
# Si no se define, se extraen automáticamente los DC= de AD_BASE_DN.
def _domain_root(base_dn: str) -> str:
    return ",".join(p for p in base_dn.split(",") if p.strip().upper().startswith("DC="))

AD_AUTH_BASE = os.getenv("AD_AUTH_BASE") or _domain_root(AD_BASE_DN)

# Timezone offset from UTC for logonHours display (hours)
TIMEZONE_OFFSET = int(os.getenv("TIMEZONE_OFFSET", 0))

# Grupos AD para acceso y permisos de operación (CN del grupo)
GROUP_ADMINISTRADORES = os.getenv("GROUP_ADMINISTRADORES", "Administradores").strip()
GROUP_GTR = os.getenv("GROUP_GTR", "GGWinGTR").strip()
GROUP_SUPER = os.getenv("GROUP_SUPER", "GWINSuper").strip()
ADMIN_GROUPS = [g.strip() for g in os.getenv("ADMIN_GROUPS", f"{GROUP_ADMINISTRADORES},{GROUP_GTR},{GROUP_SUPER}").split(",") if g.strip()]

# Flask
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key")
DEBUG      = os.getenv("DEBUG", "false").lower() == "true"
