#!/usr/bin/env python3
"""Select the same opt-in features for Apple compilation and provenance."""

import json
import os
import sys


def selected_features(environment=None, *, include_experimental=True):
    environment = os.environ if environment is None else environment
    features = []
    for variable, feature in (
        ("OTLP_EXPORT", "otlp-export"),
        ("PRODUCT_ANALYTICS_EXPORT", "product-analytics-export"),
    ):
        if environment.get(variable, "0") in {"1", "true"}:
            features.append(feature)
    if include_experimental:
        experimental = environment.get("EXPERIMENTAL_DEVICE_SYNC", "0")
        if experimental not in {"", "0", "false", "1", "true"}:
            raise ValueError("EXPERIMENTAL_DEVICE_SYNC must be 0, false, 1 or true")
        if experimental in {"1", "true"}:
            features.append("experimental-device-sync")
    return features


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in {"csv", "json"}:
            raise ValueError("usage: marmotkit_features.py csv|json")
        features = selected_features()
        print(",".join(features) if sys.argv[1] == "csv" else json.dumps(features))
    except ValueError as error:
        sys.exit(f"error: {error}")
