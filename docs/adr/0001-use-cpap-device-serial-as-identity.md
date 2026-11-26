# Use the CPAP device serial number as identity

The integration uses the device serial number as the Home Assistant config entry's unique ID and as the basis for device and sensor registry identity. An account's credentials or region can change while the same CPAP device remains configured. Tying identity to the device lets those changes preserve existing entities and keeps therapy data from a different machine from appearing under those entities.

Reauthentication and reconfiguration reject credentials that resolve to a different serial. A legacy entry without a unique ID can be assigned the serial returned after successful authentication, provided that serial is available for the entry.

[Config entry reconfiguration and legacy identity repair](https://github.com/prestomation/resmed_myair_sensors/pull/144)
