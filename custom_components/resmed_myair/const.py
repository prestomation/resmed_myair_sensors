VERSION = "0.0.0-dev"  # Version updated by release workflow

DOMAIN = "resmed_myair"
DEFAULT_UPDATE_RATE_MIN = 30

AUTHN_SUCCESS = "SUCCESS"
AUTH_NEEDS_MFA = "MFA_REQUIRED"

# Config keys
CONF_USER_NAME = "Username"
CONF_PASSWORD = "Password"
CONF_REGION = "Region"
CONF_DEVICE_TOKEN = "device_token"
CONF_VERIFICATION_CODE = "verification_code"

REGION_NA = "NA"
REGION_EU = "EU"

KEYS_TO_REDACT: list[str] = [
    "access_token",
    "Authorization",
    "email",
    "family_name",
    "firstName",
    "given_name,",
    "id_token",
    "lastName",
    "login",
    "name",
    "password",
    "Password",
    "preferred_username",
    "sub",
    "token",
    "username",
    "Username",
]
