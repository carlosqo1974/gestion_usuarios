import os
from dotenv import load_dotenv

load_dotenv()

# Active Directory connection
AD_SERVER   = os.getenv("AD_SERVER", "ldap://your-dc.domain.local")
AD_DOMAIN   = os.getenv("AD_DOMAIN", "DOMAIN")
AD_BASE_DN  = os.getenv("AD_BASE_DN", "DC=domain,DC=local")
AD_BIND_DN  = os.getenv("AD_BIND_DN", "CN=admin,CN=Users,DC=domain,DC=local")
AD_PASSWORD = os.getenv("AD_PASSWORD", "")
AD_USE_SSL  = os.getenv("AD_USE_SSL", "false").lower() == "true"
AD_PORT     = int(os.getenv("AD_PORT", 636 if AD_USE_SSL else 389))

# Base para buscar al usuario que hace LOGIN (todo el dominio por defecto).
# Si no se define, se extraen automáticamente los DC= de AD_BASE_DN.
def _domain_root(base_dn: str) -> str:
    return ",".join(p for p in base_dn.split(",") if p.strip().upper().startswith("DC="))

AD_AUTH_BASE = os.getenv("AD_AUTH_BASE") or _domain_root(AD_BASE_DN)

# Timezone offset from UTC for logonHours display (hours)
TIMEZONE_OFFSET = int(os.getenv("TIMEZONE_OFFSET", 0))

# Grupo AD requerido para acceder a la aplicación
ADMIN_GROUP = os.getenv("ADMIN_GROUP", "GWINSuper")

# Flask
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key")
DEBUG      = os.getenv("DEBUG", "false").lower() == "true"
