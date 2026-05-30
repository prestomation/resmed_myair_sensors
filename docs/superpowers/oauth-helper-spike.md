# ResMed OAuth Helper Feasibility Spike

The current integration cannot assume Home Assistant's OAuth2 helper can replace
the custom auth flow because the reverse-engineered ResMed Okta application uses
ResMed-owned redirect URLs:

- North America: `https://myair.resmed.com`
- Europe: `https://myair.resmed.eu`

Home Assistant's OAuth2 helper is still worth revisiting if ResMed exposes a
client that accepts a Home Assistant callback URL. Until then, this cleanup keeps
custom auth but isolates it behind `MyAirAuthSession` so the implementation can
be replaced later without changing sensors, coordinator, or config-flow logic.
