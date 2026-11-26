# Preserve mask-leak statistics when correcting the unit

The myAir `leakPercentile` field reports liters per minute. Older versions labeled those same values as `%` in Home Assistant. Keep the existing sensor key and unique ID, and relabel Recorder statistics metadata to `L/min` with a 1:1 unit mapping. The recorded numbers already represent the corrected unit, so preserving them keeps the existing history usable.

Run the metadata migration when Recorder is available. Sensor setup can proceed independently of Recorder.

[Sensor unit correction](https://github.com/prestomation/resmed_myair_sensors/pull/146) · [Recorder migration](https://github.com/prestomation/resmed_myair_sensors/pull/151)
