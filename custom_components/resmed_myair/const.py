"""Home Assistant entity, config-entry, and redaction constants for myAir."""

from collections.abc import Mapping

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import Platform, UnitOfTime, UnitOfVolumeFlowRate

VERSION = "v0.2.6"

DOMAIN = "resmed_myair"
PLATFORMS: list[Platform] = [Platform.SENSOR]
DEFAULT_UPDATE_RATE_MIN = 30

AUTHN_SUCCESS = "SUCCESS"
AUTH_NEEDS_MFA = "MFA_REQUIRED"

# Config keys
CONF_USER_NAME = "Username"
CONF_PASSWORD = "Password"  # noqa: S105
CONF_REGION = "Region"
CONF_DEVICE_TOKEN = "device_token"  # noqa: S105
CONF_VERIFICATION_CODE = "verification_code"

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

# Our sensor class will prepend the serial number to the key
# These sensors pass data directly from my air
SLEEP_RECORD_SENSOR_DESCRIPTIONS: Mapping[str, SensorEntityDescription] = {
    "CPAP AHI Events Per Hour": SensorEntityDescription(
        key="ahi",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "CPAP Usage Minutes": SensorEntityDescription(
        key="totalUsage",
        state_class=SensorStateClass.MEASUREMENT,
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.MINUTES,
    ),
    "CPAP Mask On/Off": SensorEntityDescription(
        key="maskPairCount",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "CPAP Current Data Date": SensorEntityDescription(
        key="startDate", device_class=SensorDeviceClass.DATE
    ),
    # Key remains leakPercentile even though units changed from % to L/min
    # to not lose sensor history
    "CPAP Mask Leak": SensorEntityDescription(
        key="leakPercentile",
        state_class=SensorStateClass.MEASUREMENT,
        device_class=SensorDeviceClass.VOLUME_FLOW_RATE,
        native_unit_of_measurement=UnitOfVolumeFlowRate.LITERS_PER_MINUTE,
    ),
    "CPAP Total myAir Score": SensorEntityDescription(
        key="sleepScore", state_class=SensorStateClass.MEASUREMENT
    ),
}

DEVICE_SENSOR_DESCRIPTIONS: Mapping[str, SensorEntityDescription] = {
    "CPAP Sleep Data Last Collected": SensorEntityDescription(
        key="lastSleepDataReportTime", device_class=SensorDeviceClass.TIMESTAMP
    )
}
