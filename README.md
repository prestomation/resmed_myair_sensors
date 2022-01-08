# resmed_myair

[![GitHub Release][releases-shield]][releases]
[![GitHub Activity][commits-shield]][commits]
[![License][license-shield]](LICENSE)

[![hacs][hacsbadge]][hacs]
![Project Maintenance][maintenance-shield]
[![Discord][discord-shield]][discord]
[![Community Forum][forum-shield]][forum]

**This component will set up the following platforms.**

| Platform | Description                   |
| -------- | ----------------------------- |
| `sensor` | Show info from the myAir API. |


## Installation

1. Using the tool of choice open the directory (folder) for your HA configuration (where you find `configuration.yaml`).
2. If you do not have a `custom_components` directory (folder) there, you need to create it.
3. In the `custom_components` directory (folder) create a new folder called `resmed_myair`.
4. Download _all_ the files from the `custom_components/resmed_myair/` directory (folder) in this repository.
5. Place the files you downloaded in the new directory (folder) you created.
6. Restart Home Assistant
7. In the HA UI go to "Configuration" -> "Integrations" click "+" and search for "ResMed myAir CPAP Sensors"
8. Enter your myAir username and password


## Features

This integration creates sensors from your myAir CPAP date like AHI Events/hr, Usage Minutes, Mask On/Off count, Mask Leak%. There is also a 'Last Sleep Data Recorded' to tell you the last date that myAir has recorded. This can be used to, say, notify you of your scores when they are updated in myAir in the morning.

By the nature of CPAP date, sensors will only update once per day(assuming your CPAP is used every day). For this reason, the integration only polls every 30 minutes.


## Sensors

The following sensors are supported in all regions:

1. CPAP AHI Events Per Hour
1. CPAP Usage Minutes
1. CPAP Mask On/Off Count
1. CPAP Current Data Date
    1. This is the last date currently being displayed by the other sensors
1. CPAP Mask Leak %
1. CPAP Total myAir Score
1. CPAP Sleep Data Last Collected
    1. This is the datetime the CPAP uploaded the most recent data. This is only supported in the Americas
1. Most Recent Sleep Date
    1. This is the most recent date for which data is available. This will match Current Data Date if you use your CPAP every day. An automation that triggers when these two sensors are different will signal that you have missed a night

## Known Issues

This integration was reversed engineered from the myAir website. There are no guarentees that this will continue to work, as this is up to the whims of ResMed. Please DO NOT rely on this for any health-related matters.

This integration currently only connects to the Americas and Europe If you are in Asia, please open an issue and offer yourself as a test subject.


## Contributions are welcome!

If you want to contribute to this please read the [Contribution guidelines](CONTRIBUTING.md)

If you want to support the development of this component, please don't donate to me but instead donate to the Home Assistant development team.

[commits-shield]: https://img.shields.io/github/commit-activity/y/prestomation/resmed_myair_sensors.svg?style=for-the-badge
[commits]: https://github.com/prestomation/resmed_myair_sensors/commits/master
[hacs]: https://github.com/custom-components/hacs
[hacsbadge]: https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge
[discord]: https://discord.gg/Qa5fW2R
[discord-shield]: https://img.shields.io/discord/330944238910963714.svg?style=for-the-badge
[forum-shield]: https://img.shields.io/badge/community-forum-brightgreen.svg?style=for-the-badge
[forum]: https://community.home-assistant.io/
[license-shield]: https://img.shields.io/github/license/prestomation/resmed_myair_sensors.svg?style=for-the-badge
[maintenance-shield]: https://img.shields.io/badge/maintainer-Preston%20Tamkin%20%40prestomation-blue.svg?style=for-the-badge
[releases-shield]: https://img.shields.io/github/release/resmed_myair_sensors.svg?style=for-the-badge
[releases]: https://github.com/prestomation/resmed_myair_sensors/releases
