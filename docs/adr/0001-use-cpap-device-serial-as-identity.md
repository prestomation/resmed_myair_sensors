# Use the CPAP device serial number as identity

The integration uses the device serial number as the Home Assistant config entry's unique ID and as the basis for device and sensor registry identity. An account's credentials or region can change while the same CPAP device remains configured. Tying identity to the device lets those changes preserve existing entities and keeps therapy data from a different machine from appearing under those entities.

Reauthentication and reconfiguration reject credentials that resolve to a different serial. A legacy entry without a unique ID can be assigned the serial returned after successful authentication, provided that serial is available for the entry.

[Config entry reconfiguration and legacy identity repair](https://github.com/prestomation/resmed_myair_sensors/pull/144)

## Enforcing the Configured CPAP Device at runtime

Every refresh compares the device myAir reports with the entry's serial. The coordinator builds all sensor unique IDs and device registry entries from the entry's serial, never from the reported device. When myAir reports another serial, the coordinator withholds the device, Sleep Record, and timeline data from the refresh. Every sensor is then unavailable, nothing is registered for the other device, the `get_nightly_timeline` action refuses the entry, and a repair issue asks the user to add the new device as its own entry. Data returns when myAir reports the configured serial again.

A refresh without a usable device payload keeps the previous decision from the same load. If no device has been reported since the entry loaded and its serial is known, its Sleep Record data is shown for that serial. A legacy entry without a unique ID uses the serial its sensors are registered under when they share one. When sensors exist under more than one serial, the entry uses the serial myAir reports at its first refresh if it is one of them. Otherwise, including when that refresh has no device payload, it uses the lowest-sorting registered serial until the entry reloads, so a later report of another registered serial is treated as a different device. With no registered or reported serial, the entry withholds its data. Sensors built before the serial is known get provisional unique IDs. Once the serial is known, their registry entries move to serial-based unique IDs, unless a sensor with the target unique ID is already registered. A sensor built before the serial was known keeps its provisional unique ID and has no device until the entry reloads. Sensors registered with a blank serial move in the same way, keeping their entity IDs and opt-ins.

Before this, only Time in Apnea and the Nightly Timeline followed the entry's serial. A replacement device registered new sensors on a new device under the original entry, and the original sensors became unavailable. After the change, those sensors return to the configured serial and stay unavailable while myAir reports the replacement. Adding the replacement device as a new entry adopts the sensors it registered earlier, keeping their entity IDs.

## Obsolete issue for entries created with email MFA

In v0.2.0 through v0.2.6, setup with email MFA could create a Home Assistant entry without saving the CPAP device serial number as its unique ID. If that entry later reauthenticated with a serial already assigned to another entry, both entries could claim the same device. Setup has saved the serial on both sign-in paths since v0.2.7, so this issue no longer applies to newly created entries.
