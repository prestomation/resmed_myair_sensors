"""Constants for ResMed myAir Client."""

AUTHN_SUCCESS = "SUCCESS"
AUTH_NEEDS_MFA = "MFA_REQUIRED"

REGION_NA = "NA"
REGION_EU = "EU"

KEYS_TO_REDACT: list[str] = [
    "access_token",
    "Authorization",
    "email",
    "family_name",
    "firstName",
    "given_name",
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
