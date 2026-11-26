# Observed myAir API

This maintainer reference records a live integration smoke test, two Firefox captures, and GraphQL operations from myAir for Android 5.6.0.0.740. Live verification on November 25, 2026 used one signed-in account. Use the [curated GraphQL schema](../scripts/graphql_schema.json) for the integration's current query documents and known field types.

## Regional URLs

| Observed in | URL |
| --- | --- |
| Integration configuration for North America and Australia | `https://graphql.myair-prd.dht.live/graphql` |
| Integration configuration for Europe | `https://graphql.hyperdrive.resmed.eu/graphql` |
| Signed-in Firefox web client and observed iOS connection | `https://graphql.prd.hyperdrive.myair.resmed.com/graphql` |

The Firefox host returned HTTP 200 for all five captured operations. An authenticated comparison also ran `GetDailyTherapyData` and `GetTrends` on both the configured North American host and the Firefox host with identical variables. Both hosts returned HTTP 200, no GraphQL errors, and identical `data` for each operation. The comparison covered one North American account. Europe was outside that test.

### Identity and assets

| Route | OAuth redirect URL configured in the integration | OpenID issuer configured in the integration |
| --- | --- | --- |
| North America and Australia (`NA`) | `https://myair.resmed.com` | `https://resmed-ext-1.okta.com/oauth2/aus4ccsxvnidQgLmA297` |
| Europe (`EU`) | `https://myair.resmed.eu` | `https://id.resmed.eu/oauth2/aus2uznux2sYKTsEg417` |

Public OpenID discovery returned HTTP 200 for both configured issuers and for these additional issuer URLs on the Android app's production identity host. Authentication through the alternate host was outside the test.

- [North America discovery](https://resmed-ext-1.okta.com/oauth2/aus4ccsxvnidQgLmA297/.well-known/openid-configuration)
- [Europe discovery](https://id.resmed.eu/oauth2/aus2uznux2sYKTsEg417/.well-known/openid-configuration)
- [Alternate North American issuer discovery](https://id.resmed.com/oauth2/aus4ccsxvnidQgLmA297/.well-known/openid-configuration)
- [Alternate host's organization-level issuer discovery](https://id.resmed.com/.well-known/openid-configuration)

The configured and alternate custom issuers advertised `/v1/authorize`, `/v1/token`, `/v1/userinfo`, `/v1/introspect`, and `/v1/keys` below the issuer URL. The organization-level issuer advertised the corresponding paths under `/oauth2/v1/`.

| Additional Android configuration | Public check |
| --- | --- |
| `https://id-ps.resmed.eu/`, labeled `EU_PROD_SUPPORT` | [Organization-level discovery](https://id-ps.resmed.eu/.well-known/openid-configuration) returned HTTP 200. The discovery path for the integration's EU custom issuer ID returned HTTP 404 on this host. |
| `https://assets.prd.hyperdrive.myair.resmed.com`, labeled `PRODUCTION` | An unauthenticated request to `/v2/masks/mask_assets.json` returned HTTP 400. |
| `https://assets.hyperdrive.resmed.eu`, labeled `EU_PRODUCTION` | An unauthenticated request to `/v2/masks/mask_assets.json` returned HTTP 400. |

The [region configuration](../custom_components/resmed_myair/client/regions.py) defines the issuer, redirect URL, product label, OAuth client ID, GraphQL API key, and MFA factor fallback. The [authentication client](../custom_components/resmed_myair/client/auth.py) posts to `/api/v1/authn` at the identity host. For an email-factor challenge, it uses the verification link from the auth response when present, with `/api/v1/authn/factors/{factor_id}/verify?rememberDevice=true` as the configured fallback. It exchanges the session token for an authorization code using PKCE. The [GraphQL client](../custom_components/resmed_myair/client/graphql.py) posts `operationName`, `query`, and `variables` with the OAuth bearer token, the regional API key and product label, and `rmdcountry` from the ID token's `myAirCountryId` claim. The configured region selects the endpoints independently of the country claim.

### Additional markets

The integration's [setup form](../custom_components/resmed_myair/config_flow.py) exposes North America and Australia, and Europe with email MFA. ResMed's [5.5 release notes](https://document.resmed.com/documents/products/data-management/myair/release-note/108376_myair-by-resmed-5.5_release-notes_glo_eng.pdf) distinguish availability of the web and mobile clients.

| Markets outside the integration's documented coverage | Evidence and current limits |
| --- | --- |
| New Zealand, Argentina, Brazil, Chile, Colombia, Mexico | ResMed groups these with Australia and the US for web and mobile app availability. No account from these markets was authenticated in this investigation. |
| Indonesia, Japan, Taiwan, Thailand, Vietnam | ResMed lists both web and app availability. ResMed Japan's [myAir page](https://www.resmed.jp/product/myair) links to the global web country selector. The Android APK inspected here was the global `com.resmed.myair` package. |
| Hong Kong, India, Malaysia, Philippines, Singapore, South Korea | ResMed lists these markets for the mobile app. The separate [myAir Asia package](https://play.google.com/store/apps/details?id=com.resmed.myair.apac) is `com.resmed.myair.apac`. Its identity host, MFA flow, GraphQL URL, and field availability remain unverified. A user in India reported mobile access and no web access in [issue #70](https://github.com/prestomation/resmed_myair_sensors/issues/70). |
| South Africa | ResMed lists web and app availability in its Europe group. The integration's Europe route was outside this investigation's live tests. |

## Nightly sleep records and scores

The integration and the web client's `GetPatientSleepRecords` both select `getPatientWrapper.sleepRecords.items`. Every captured web response used the same item fields as the smoke test. The fields include the assigned date (`startDate`), usage (`totalUsage`), nightly AHI (`ahi`), mask on/off count (`maskPairCount`), mask leak (`leakPercentile`), total score (`sleepScore`), and the four component scores.

| Score component | API field | Maximum points |
| --- | --- | ---: |
| Therapy usage | `usageScore` | 70 |
| Mask seal | `leakScore` | 20 |
| Events per hour | `ahiScore` | 5 |
| Mask on/off | `maskScore` | 5 |

All four component fields were non-null in all 55 records from the live smoke test. The integration already fetched them when [issue #131](https://github.com/prestomation/resmed_myair_sensors/issues/131) was investigated. The point limits come from [ResMed's score breakdown](https://document.resmed.com/en-us/documents/articles/1018645-myAir.pdf).

The smoke test's `--raw` option includes the device and sleep-record fields returned for the client's fixed queries. The nightly `startDate` and device-level `lastSleepDataReportTime` describe the record date and report time, respectively. The Firefox sleep-record queries contain no individual respiratory events, event types, per-event timestamps, or oxygen readings.

An authenticated test added `apneaIndex` and `hypopneaIndex` to the existing `GetPatientSleepRecords` selection at `getPatientWrapper.sleepRecords.items`, using its inline date arguments. Both fields returned values with HTTP 200 and no GraphQL errors. The [sensor descriptions](../custom_components/resmed_myair/const.py) and [models](../custom_components/resmed_myair/models.py) record the integration's current field mappings. For example, it reads `totalUsage` as minutes and exposes `leakPercentile` as L/min. The [mask leak decision](adr/0003-preserve-mask-leak-statistics-when-correcting-units.md) explains why the existing key is retained.

## Additional GraphQL fields observed in Firefox

| Operation | Fields and response context |
| --- | --- |
| `GetFeatureMetadata` | `getFeatureMetadata.dataExperience.timelineEnabled`, `equipmentManagement.enabled`, and `deviceControl.enabled` were true in this capture. `equipmentManagement.scheduleConfig` included cushion type and material and minimum, maximum, and recommended recurrence days. These are feature settings and schedule configuration. |
| `GetPatientSleepRecords` | The web client used two query variants under this operation name. A variant also returned `getPatientWrapper.patient.timezoneId`, mask and device metadata, and an empty `notifications` array. The time zone is useful context if a later operation returns local timestamps. |
| `GetPatientDevice` | `getPatientWrapper.fgDevices[].imagePath` was populated. `patient.journeys` was populated, and `notifications` was empty. |
| `getPatientWrapper` | `getPatientWrapper.masks[]` included `localizedName`, `maskManufacturerName`, `maskType`, and `imagePath` in addition to the already-used `maskCode`. The response also included device imagery, patient settings, dashboard cards, coaching history, consent records, and sleep-library content. |
| `GetPatientAnalytics` | Returned analytics, demographic, and provider-sharing setting fields under `getPatientWrapper.patient`. |

The second capture repeated the same GraphQL operations and response fields. The inventory above reflects returned JSON paths. It establishes field presence for the captured account, without establishing GraphQL nullability or availability across regions or device models.

## Nightly Therapy Timeline

The Android APK contains the `GetDailyTherapyData` operation. A live request using the integration's existing authentication and configured GraphQL host returned HTTP 200 without GraphQL errors. Passing the same calendar date for both variables returned one day's data for the tested night.

```graphql
query GetDailyTherapyData($startDate: AWSDate!, $endDate: AWSDate!) {
  getPatientWrapper {
    dailyTherapyData(startDate: $startDate, endDate: $endDate) {
      date
      ahi
      totalUsageHours
      totalSecondsInApnea
      respiratoryEvents {
        startDate
        endDate
        durationSeconds
        eventType
      }
      therapyStatusEvents {
        date
        eventType
      }
    }
  }
}
```

- `respiratoryEvents` returned per-event start and end timestamps, duration in seconds, and event type. Observed types included `centralApnea`, `hypopnea`, and `obstructiveApnea`.
- `therapyStatusEvents` returned timestamped `maskOn`, `maskOff`, `therapyStart`, and `therapyStop` events.
- Both sets used ISO 8601 datetimes with a timezone designator. These are the event types and timestamps requested in [issue #211](https://github.com/prestomation/resmed_myair_sensors/issues/211). Oxygen readings are outside this operation's selection.

## Additional Android GraphQL operations

These operations also returned HTTP 200 without GraphQL errors using the integration's existing authentication.

| Operation | Fields verified in the live response |
| --- | --- |
| `GetTrends($startMonth: AWSDate!, $endMonth: AWSDate!)` | `getPatientWrapper.sleepRecords.items` included populated `apneaIndex` and `hypopneaIndex`. The query also selected `min`, `max`, and `median` for `leak`, `inspiratoryPressure`, `respiratoryRate`, `tidalVolume`, and `minuteVentilation`. Those five objects were null in the returned records. |
| `GetSleepSummary($date: AWSDate!)` | `getPatientWrapper.sleepSummary.totalUsageHours` was populated. `totalTimeAsleepMinutes`, `totalTimeInBedMinutes`, and `sleepSessions` were null. The query selects session start and end, time asleep, duration, and samples with start, end, and sleep stage. It also selects the patient's health-sharing settings. |
| `GetEquipment` | `resupplyInfo` returned `dueDate` and `totalDays`. The CPAP and mask component lists returned replacement information with `dueDate`, `totalDays`, and `remainingDays`. The query also selects mask cushion type and material, device and mask image URLs, and equipment schedule configuration. |

### Query documents

The following documents reproduce the selections in the Android APK, with whitespace added for readability. Date variables use `YYYY-MM-DD`. The `GetTrends` arguments are named `startMonth` and `endMonth`; their exact range semantics were outside the test.

```graphql
query GetTrends($startMonth: AWSDate!, $endMonth: AWSDate!) {
  getPatientWrapper {
    sleepRecords(startMonth: $startMonth, endMonth: $endMonth) {
      items {
        startDate
        sleepRecordPatientId
        totalUsage
        sleepScore
        usageScore
        ahiScore
        maskScore
        leakScore
        ahi
        apneaIndex
        hypopneaIndex
        maskPairCount
        leak { min max median }
        inspiratoryPressure { min max median }
        respiratoryRate { min max median }
        tidalVolume { min max median }
        minuteVentilation { min max median }
        leakPercentile
      }
    }
  }
}

query GetSleepSummary($date: AWSDate!) {
  getPatientWrapper {
    patient {
      healthSharingEnabled
      healthSharingLastPromptedVersion
    }
    sleepSummary(date: $date) {
      totalTimeAsleepMinutes
      totalTimeInBedMinutes
      totalUsageHours
      sleepSessions {
        startTime
        endTime
        timeAsleepSeconds
        durationSeconds
        sleepSamples { startTime endTime stage }
      }
    }
  }
}

query GetEquipment {
  getPatientWrapper {
    resupplyInfo {
      dueDate
      totalDays
      hmeInfo { name phoneNumber email websiteUrl imageUrl }
    }
    fgDevices {
      serialNumber
      deviceSeries
      deviceFamily
      localizedName
      lastSleepDataReportTime
      imageUrl
      deviceSubtype
      fgComponents: components {
        componentType
        imageUrl
        localizedName
        fgComponentReplacementInfo: replacementInfo { dueDate totalDays remainingDays }
      }
    }
    masks {
      manufacturer
      maskManufacturerName
      maskCode
      localizedName
      imageUrl
      cushionType
      cushionMaterial
      maskComponents: components {
        componentType
        imageUrl
        localizedName
        maskComponentReplacementInfo: replacementInfo { dueDate totalDays remainingDays }
      }
    }
    notifications { id action title description positiveButtonTitle negativeButtonTitle url imageUrl }
  }
  getFeatureMetadata {
    dawn { enabled myTherapyNavigatorEnabled url }
    streaks { enabled }
    deviceControl { enabled version }
    equipmentManagement {
      enabled
      marketType
      estimatedDates { estimatedDate isLastOrderDateEstimated isLastReplacementDateEstimated }
      scheduleConfig {
        __typename
        ... on ResupplyScheduleConfigItem { recommendedRecurrenceDays minRecurrenceDays maxRecurrenceDays }
        ... on FgEquipmentReplacementScheduleConfigItem {
          fgComponentType: componentType
          recommendedRecurrenceDays
          minRecurrenceDays
          maxRecurrenceDays
        }
        ... on MaskEquipmentReplacementScheduleConfigItem {
          maskComponentType: componentType
          cushionType
          cushionMaterial
          recommendedRecurrenceDays
          minRecurrenceDays
          maxRecurrenceDays
        }
      }
    }
    sleepTest { enabled }
  }
}
```

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

- The Nightly Therapy Timeline was visible in the iOS app and did not appear in the web interface for the account tested, even though the web response reported `timelineEnabled: true`. Firefox recorded no timeline request. The iOS connection closed during the proxy's TLS handshake, before an HTTP request was captured. The query above came from the Android APK and was verified independently against the live API. ResMed lists the feature in the [5.5 release notes](https://document.resmed.com/documents/products/data-management/myair/release-note/108376_myair-by-resmed-5.5_release-notes_glo_eng.pdf) alongside myAir web 3.48.
- The Android operations were verified for one account and region. Availability of detailed trends and sleep-stage data remains unverified.
- The [schema notes](../scripts/graphql_schema.json) record that `__typename` works and standard GraphQL schema introspection fields return `FieldUndefined`. Additional client requests can reveal more fields and operations. When recording those, retain operation names, URL paths, and response shapes, with credentials, identifiers, and personal therapy values omitted.
