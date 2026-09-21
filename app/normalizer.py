from __future__ import annotations

from app.models import NormalizedConfig


def validate_normalized(config: NormalizedConfig) -> None:
    # Important: missing != false. The compliance engine handles missing fields explicitly.
    if not config.device.vendor:
        raise ValueError("Normalized config is missing vendor identity.")
