"""Read config.json and check that every setting is present and sensible.

All numbers that change the result live in config.json, not in the code,
so a threshold can be changed without editing Python code.
"""

import json


class ConfigError(Exception):
    """config.json is missing, broken, or has a bad value."""


# Every key config.json must have, and the type its value must have.
REQUIRED_KEYS = {
    "fanout_min_destinations": int,
    "upload_min_src_bytes": int,
    "time_format": str,
    "plot_top_n": int,
}


def load_config(path):
    """Return the settings from `path` as a dict, or raise ConfigError."""
    try:
        with open(path, encoding="utf-8") as file:
            config = json.load(file)
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}")
    except json.JSONDecodeError as error:
        raise ConfigError(f"config file is not valid JSON: {error}")

    if not isinstance(config, dict):
        raise ConfigError("config file must contain a JSON object { ... }")

    for key, expected_type in REQUIRED_KEYS.items():
        if key not in config:
            raise ConfigError(f"config is missing the key '{key}'")
        value = config[key]
        # bool is a kind of int in Python, so reject true/false explicitly.
        if not isinstance(value, expected_type) or isinstance(value, bool):
            raise ConfigError(f"'{key}' must be of type {expected_type.__name__}, got {value!r}")
        if expected_type is int and value < 1:
            raise ConfigError(f"'{key}' must be at least 1, got {value}")
    return config
