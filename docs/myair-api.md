# Observed myAir API

This maintainer reference records a live integration smoke test and two Firefox captures from November 25, 2026. The captures cover one signed-in account. Use the [curated GraphQL schema](../scripts/graphql_schema.json) for the integration's query documents and known field types.

## GraphQL hosts

| Observed in | URL |
| --- | --- |
| Integration configuration for North America | `https://graphql.myair-prd.dht.live/graphql` |
| Integration configuration for Europe | `https://graphql.hyperdrive.resmed.eu/graphql` |
| Signed-in Firefox web client | `https://graphql.prd.hyperdrive.myair.resmed.com/graphql` |

The Firefox host returned HTTP 200 for all five captured GraphQL operations. Compatibility between the web host and the integration's authentication flow remains unverified. See the [integration's region configuration](../custom_components/resmed_myair/client/regions.py) for the configured hosts.

## Nightly sleep records and scores

The integration and the web client's `GetPatientSleepRecords` both select `getPatientWrapper.sleepRecords.items`. Every captured web response used the same item fields as the smoke test. The fields include the assigned date (`startDate`), usage (`totalUsage`), nightly AHI (`ahi`), mask on/off count (`maskPairCount`), mask leak (`leakPercentile`), total score (`sleepScore`), and the four component scores.

| Score component | API field | Maximum points |
| --- | --- | ---: |
| Therapy usage | `usageScore` | 70 |
| Mask seal | `leakScore` | 20 |
| Events per hour | `ahiScore` | 5 |
| Mask on/off | `maskScore` | 5 |

All four component fields were non-null in all 55 records from the live smoke test. The integration already fetched them when [issue #131](https://github.com/prestomation/resmed_myair_sensors/issues/131) was investigated. The point limits come from [ResMed's score breakdown](https://document.resmed.com/en-us/documents/articles/1018645-myAir.pdf).

The smoke test's `--raw` option includes the device and sleep-record fields returned for the client's fixed queries. The nightly `startDate` and device-level `lastSleepDataReportTime` describe the record date and report time, respectively. The queries in these captures contain no individual respiratory events, event types, per-event timestamps, or oxygen readings.

## Additional GraphQL fields observed in Firefox

| Operation | Fields and response context |
| --- | --- |
| `GetFeatureMetadata` | `getFeatureMetadata.dataExperience.timelineEnabled`, `equipmentManagement.enabled`, and `deviceControl.enabled` were true in this capture. `equipmentManagement.scheduleConfig` included cushion type and material and minimum, maximum, and recommended recurrence days. These are feature settings and schedule configuration. |
| `GetPatientSleepRecords` | The web client used two query variants under this operation name. A variant also returned `getPatientWrapper.patient.timezoneId`, mask and device metadata, and an empty `notifications` array. The time zone is useful context if a later operation returns local timestamps. |
| `GetPatientDevice` | `getPatientWrapper.fgDevices[].imagePath` was populated. `patient.journeys` was populated, and `notifications` was empty. |
| `getPatientWrapper` | `getPatientWrapper.masks[]` included `localizedName`, `maskManufacturerName`, `maskType`, and `imagePath` in addition to the already-used `maskCode`. The response also included device imagery, patient settings, dashboard cards, coaching history, consent records, and sleep-library content. |
| `GetPatientAnalytics` | Returned analytics, demographic, and provider-sharing setting fields under `getPatientWrapper.patient`. |

The second capture repeated the same GraphQL operations and response fields. The inventory above reflects returned JSON paths. It establishes field presence for the captured account, without establishing GraphQL nullability or availability across regions or device models.

## REST endpoints and static assets

| Method and URL | Observed response |
| --- | --- |
| `GET https://rest.prd.hyperdrive.myair.resmed.com/V1/Patient/SummaryReport` | JSON with `result.success` and base64-encoded PDF data in `entity.content`. No URL query parameters appeared in the capture. |
| `POST https://rest.prd.hyperdrive.myair.resmed.com/V1/Patient/RegisterApplication` | HTTP 200 with `result.success` and an empty `entity` object. |
| `POST https://rest.prd.hyperdrive.myair.resmed.com/V2/Patient/PatientMessagingApi` | The captured request included `timeZone`. Responses had `result.success` and an empty `entity` object. |
| `GET https://static.myair-prd.dht.live/v2/masks/mask_assets.json` | Catalog grouped by manufacturer, mask family, and model, with mask codes, names, types, and asset paths. |

The second capture added `SummaryReport`. The decoded PDF contains 30-, 90-, and 365-day summaries, including days used, days with at least four hours of use, average usage, AHI, and mask leak. The response supplies a downloadable report. Its JSON wrapper contains the file and status rather than individual metric fields. Access through the integration's authentication flow has yet to be tested.

The captures also included Okta sign-in and an AWS Lambda URL that returned `dev` and `prod` URLs. Neither response supplied therapy records.

## Discovery limits

- The Nightly Therapy Timeline was visible in the iOS myAir app and did not appear in the web interface for the account tested, even though the web capture reported `timelineEnabled: true`. Neither Firefox capture included a timeline request. The operation, endpoint, event types, and timestamp format remain unknown for [issue #211](https://github.com/prestomation/resmed_myair_sensors/issues/211). ResMed lists the feature in the [5.5 release notes](https://document.resmed.com/documents/products/data-management/myair/release-note/108376_myair-by-resmed-5.5_release-notes_glo_eng.pdf) alongside myAir web 3.48.
- Equipment management was enabled in the feature metadata. Neither capture included an account-specific equipment replacement schedule.
- The [schema notes](../scripts/graphql_schema.json) record that `__typename` works and standard GraphQL schema introspection fields return `FieldUndefined`. Additional client requests can reveal more fields and operations. When recording those, retain operation names, URL paths, and response shapes, with credentials, identifiers, and personal therapy values omitted.
