"""Structured logging checks shared by the independently built services."""

import json
import logging

import pytest
from cloud.logging_config import JsonLineFormatter as CloudFormatter
from device.logging_config import JsonLineFormatter as DeviceFormatter
from gateway.logging_config import JsonLineFormatter as GatewayFormatter


@pytest.mark.parametrize(
    ("service", "formatter_type"),
    [
        ("device", DeviceFormatter),
        ("gateway", GatewayFormatter),
        ("cloud", CloudFormatter),
    ],
)
def test_jsonl_formatter_is_structured_and_resists_field_injection(
    service: str, formatter_type: type[logging.Formatter]
) -> None:
    record = logging.LogRecord(
        service,
        logging.INFO,
        __file__,
        1,
        "event=%s observation_id=%s\nforged=true",
        ("observation_accepted", "device-1:2024-01-01"),
        None,
    )
    record.__dict__.update(
        {
            "event": "observation_accepted",
            "observation_id": "device-1:2024-01-01",
            "result": "stored",
            "authorization": "Bearer SECRET_SENTINEL",
            "otelTraceID": "1" * 32,
            "otelSpanID": "2" * 16,
        }
    )

    line = formatter_type(service).format(record)
    payload = json.loads(line)

    assert "\n" not in line
    assert payload["timestamp"].endswith("Z")
    assert payload["service"] == service
    assert payload["level"] == "info"
    assert payload["event"] == "observation_accepted"
    assert payload["observation_id"] == "device-1:2024-01-01"
    assert payload["result"] == "stored"
    assert payload["trace_id"] == "1" * 32
    assert payload["span_id"] == "2" * 16
    assert "authorization" not in payload
    assert "SECRET_SENTINEL" not in line
    assert len(line.splitlines()) == 1
