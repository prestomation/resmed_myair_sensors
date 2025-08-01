# resmed_myair

[![GitHub Downloads][downloads-shield]][releases]
[![GitHub Latest Downloads][downloads-latest-shield]][releases]
[![GitHub Release][releases-shield]][releases]
[![GitHub Release Date][release-date-shield]][releases]
[![GitHub Activity][commits-shield]][commits]
[![License][license-shield]](LICENSE)
[![hacs][hacsbadge]][hacs]
![Project Maintenance][maintenance-shield]

## Features

This integration creates sensors from your myAir CPAP data like AHI Events/hr, Usage Minutes, Mask On/Off count, Mask Leak %. There is also a Last Sleep Data Recorded sensor to tell you the last date that myAir has recorded. This can be used to, say, notify you of your scores when they are updated in myAir in the morning.

By the nature of CPAP data, sensors will only update once per day (assuming your CPAP is used every day). For this reason, the integration only polls every 30 minutes. A service exists for each config that will force update if you want to automate the sync after you wake up.

## Installation via HACS

* Ensure that [HACS](https://hacs.xyz/) is installed

* <a href="https://my.home-assistant.io/redirect/hacs_repository/?owner=prestomation&repository=resmed_myair_sensors" target="_blank" rel="noreferrer noopener"><img src="https://my.home-assistant.io/badges/hacs_repository.svg" alt="Open your Home Assistant instance to download the ResMed integration." /></a>

  * Find the ResMed integration in the HACS integration list and Download it

* Restart Home Assistant

* <a href="https://my.home-assistant.io/redirect/config_flow_start/?domain=resmed_myair" target="_blank" rel="noreferrer noopener"><img src="https://my.home-assistant.io/badges/config_flow_start.svg" alt="Open your Home Assistant instance to setup the ResMed integration." /></a>

  * Add the ResMed integration using the standard integration UI in Home Assistant

## Sensors

1. CPAP AHI Events Per Hour
1. CPAP Usage Minutes
1. CPAP Mask On/Off Count
1. CPAP Current Data Date
    * This is the last date currently being displayed by the other sensors
1. CPAP Mask Leak %
1. CPAP Total myAir Score
1. CPAP Sleep Data Last Collected
    * This is the datetime the CPAP uploaded the most recent data
1. Most Recent Sleep Date
    * This is the most recent date for which data is available. This will match Current Data Date if you use your CPAP every day. An automation that triggers when these two sensors are different will signal that you have missed a night

## Services

Each config entry for this integration will create a service called `resmed_myair.force_poll_{username}` that will force an update from myAir.

## Known Issues

This integration was reversed engineered from the myAir website. There are no guarantees that this will continue to work, as this is up to the whims of ResMed. Please DO NOT rely on this for any health-related matters.

This integration currently only connects to accounts from North America, Europe, and Australia. If you are in Asia and have access to the ResMed myAir website in your country (<https://myair.resmed.com>), please open an issue and offer yourself as a test subject.

## Contributions are welcome!

If you want to contribute to this please read the [Contribution guidelines](CONTRIBUTING.md)

If you want to support the development of this component, please don't donate to me but instead donate to the Home Assistant development team.

[commits-shield]: https://img.shields.io/github/last-commit/prestomation/resmed_myair_sensors?style=for-the-badge
[commits]: https://github.com/prestomation/resmed_myair_sensors/commits/main
[hacs]: https://github.com/custom-components/hacs
[hacsbadge]: https://img.shields.io/badge/HACS-Default-blue.svg?style=for-the-badge
[license-shield]: https://img.shields.io/github/license/prestomation/resmed_myair_sensors.svg?style=for-the-badge
[maintenance-shield]: https://img.shields.io/badge/Maintainers-%40prestomation%20%40Snuffy2-blue.svg?style=for-the-badge
[downloads-shield]: https://img.shields.io/github/downloads/prestomation/resmed_myair_sensors/total.svg?style=for-the-badge
[downloads-latest-shield]: https://img.shields.io/github/downloads-pre/prestomation/resmed_myair_sensors/latest/total?style=for-the-badge
[releases-shield]: https://img.shields.io/github/release/prestomation/resmed_myair_sensors.svg?style=for-the-badge
[release-date-shield]: https://img.shields.io/github/release-date/prestomation/resmed_myair_sensors?style=for-the-badge
[releases]: https://github.com/prestomation/resmed_myair_sensors/releases
