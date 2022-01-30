[![GitHub Release][releases-shield]][releases]
[![GitHub Activity][commits-shield]][commits]
[![License][license-shield]][license]

[![hacs][hacsbadge]][hacs]
[![Project Maintenance][maintenance-shield]][user_profile]

[![Discord][discord-shield]][discord]
[![Community Forum][forum-shield]][forum]


**This component will set up the following platforms.**

| Platform | Description                                      |
| -------- | ------------------------------------------------ |
| `sensor` | Show CPAP daily stats from the ResMed myAir API. |


{% if not installed %}
## Installation

1. Click install.
1. In the HA UI go to "Configuration" -> "Integrations" click "+" and search for "ResMed myAir CPAP Sensors".

{% endif %}


## Configuration is done in the UI

1. Enter your username and password
2. Sensor entities will be created with the prefix `cpap_`

***

[resmed_myair_sensors]: https://github.com/prestomation/resmed_myair_sensors
[commits-shield]: https://img.shields.io/github/commit-activity/y/prestomation/resmed_myair_sensors.svg?style=for-the-badge
[commits]: https://github.com/prestomation/resmed_myair_sensors/commits/master
[hacs]: https://hacs.xyz
[hacsbadge]: https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge
[discord]: https://discord.gg/Qa5fW2R
[discord-shield]: https://img.shields.io/discord/330944238910963714.svg?style=for-the-badge
[forum-shield]: https://img.shields.io/badge/community-forum-brightgreen.svg?style=for-the-badge
[forum]: https://community.home-assistant.io/
[license]: https://github.com/prestomation/resmed_myair_sensors/blob/main/LICENSE
[license-shield]: https://img.shields.io/github/license/prestomation/resmed_myair_sensors.svg?style=for-the-badge
[maintenance-shield]: https://img.shields.io/badge/maintainer-Preston%20Tamkin%20%40prestomationblue.svg?style=for-the-badge
[releases-shield]: https://img.shields.io/github/release/prestomation/resmed_myair_sensors.svg?style=for-the-badge
[releases]: https://github.com/prestomation/resmed_myair_sensors/releases
[user_profile]: https://github.com/prestomation
