CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    observed_on DATE NOT NULL,
    latitude DOUBLE PRECISION NOT NULL CHECK (latitude BETWEEN -90 AND 90),
    longitude DOUBLE PRECISION NOT NULL CHECK (longitude BETWEEN -180 AND 180),
    elevation_m DOUBLE PRECISION NOT NULL,
    utc_offset_seconds INTEGER NOT NULL CHECK (utc_offset_seconds BETWEEN -43200 AND 50400),
    timezone TEXT NOT NULL,
    timezone_abbreviation TEXT NOT NULL,
    temperature_max_c DOUBLE PRECISION NOT NULL,
    temperature_min_c DOUBLE PRECISION NOT NULL,
    precipitation_mm DOUBLE PRECISION NOT NULL CHECK (precipitation_mm >= 0),
    wind_speed_max_kmh DOUBLE PRECISION NOT NULL CHECK (wind_speed_max_kmh >= 0),
    received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (temperature_min_c <= temperature_max_c)
);
