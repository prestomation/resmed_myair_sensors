# resmed_myair

[![GitHub Downloads][downloads-shield]][releases]
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

### Installation via HACS

Unless you have a good reason not to, you probably want to install this component via HACS (Home Assistant Community Store)
1. Ensure that [HACS](https://hacs.xyz/) is installed.
1. Navigate to HACS -> Integrations
1. Open the three-dot menu and select 'Custom Repositories'
1. Put 'https://github.com/prestomation/resmed_myair_sensors/' into the 'Repository' textbox.
1. Select 'Integration' as the category
1. Press 'Add'.
1. Find the ResMed integration in the HACS integration list and install it
1. Restart Home Assistant.
1. Add a configuration for the integration in the standard integration UI in Home Assistant.

<details>
<summary><h3>Manual Installation</h3></summary>

You probably do not want to do this! Use the HACS method above unless you have a very good reason why you are installing manually

If you do need to install manually, you will know how this is done. You can install from source or use the latest release.
</details>

## Features

This integration creates sensors from your myAir CPAP data like AHI Events/hr, Usage Minutes, Mask On/Off count, Mask Leak %. There is also a Last Sleep Data Recorded sensor to tell you the last date that myAir has recorded. This can be used to, say, notify you of your scores when they are updated in myAir in the morning.

By the nature of CPAP data, sensors will only update once per day (assuming your CPAP is used every day). For this reason, the integration only polls every 30 minutes. A service exists for each config that will force update if you want to automate the sync after you wake up.

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

## Services

Each config entry for this integration will create a service called `resmed_myair.force_poll_{username}` that will force an update from myAir.

## Known Issues

This integration was reversed engineered from the myAir website. There are no guarantees that this will continue to work, as this is up to the whims of ResMed. Please DO NOT rely on this for any health-related matters.

This integration currently only connects to the Americas and Europe. If you are in Asia, please open an issue and offer yourself as a test subject.

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
[downloads-shield]: https://img.shields.io/github/downloads/prestomation/resmed_myair_sensors/total.svg?style=for-the-badge
[releases-shield]: https://img.shields.io/github/release/prestomation/resmed_myair_sensors.svg?style=for-the-badge
[releases]: https://github.com/prestomation/resmed_myair_sensors/releases
