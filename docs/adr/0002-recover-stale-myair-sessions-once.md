# Retry a stale myAir session once per refresh

Okta can report an access token as active even after the myAir data API stops returning the expected payload. Reuse an active token during routine polling, and allow one fresh login per coordinator refresh when a data response indicates a stale session. This recovers from the mismatch without requiring a sign-in on every poll or asking the user to reauthenticate for a transient failure.

If login fails with an authentication error, Home Assistant starts reauthentication. An empty sleep-record list is a valid response and does not trigger another login. When myAir reports maintenance, fail the refresh and use the reported outage end to defer the next poll when that time is known and still in the future.

[Stale-session recovery](https://github.com/prestomation/resmed_myair_sensors/pull/173) · [Maintenance handling](https://github.com/prestomation/resmed_myair_sensors/pull/206)
