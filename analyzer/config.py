"""Read config.json and check that every setting is present and sensible.

All numbers that change the result live in config.json, not in the code,
so a threshold can be changed without editing Python code.
"""

import json
import os


class ConfigError(Exception):
    """config.json is missing, broken, or has a bad value."""


SIGNAL_NAMES = ["fanout", "large_upload", "failed_tcp", "port_scan", "burst", "beaconing", "blocklist"]

# Every setting the program needs: (path inside the JSON, type, smallest allowed value).
# "number" accepts 3 and 3.5; None as the minimum means "no minimum".
REQUIRED = [
    (("time_format",), str, None),
    (("window_seconds",), int, 1),
    (("monitored_prefix",), str, None),
    (("blocklist_file",), str, None),
    (("plot_top_n",), int, 1),
    (("signals", "fanout", "threshold"), int, 1),
    (("signals", "large_upload", "threshold"), int, 1),
    (("signals", "failed_tcp", "threshold"), "number", 0),
    (("signals", "failed_tcp", "min_attempts"), int, 1),
    (("signals", "port_scan", "threshold"), int, 1),
    (("signals", "burst", "percentile"), "number", 0),
    (("signals", "burst", "min_flows"), int, 1),
    (("signals", "beaconing", "max_cv"), "number", 0),
    (("signals", "beaconing", "min_flows"), int, 3),
    (("severity", "low"), int, 1),
    (("severity", "medium"), int, 1),
    (("severity", "high"), int, 1),
    (("ml", "enabled"), bool, None),
    (("ml", "model_file"), str, None),
    (("ml", "min_probability"), "number", 0),
    (("ml", "points"), int, 0),
]
for _name in SIGNAL_NAMES:
    REQUIRED.append((("signals", _name, "points"), int, 0))
    REQUIRED.append((("signals", _name, "group"), str, None))


def value_at(config, path):
    """config["signals"]["fanout"]["threshold"] for path ("signals", "fanout", "threshold")."""
    value = config
    for key in path:
        if not isinstance(value, dict) or key not in value:
            raise ConfigError(f"config is missing the key '{'.'.join(path)}'")
        value = value[key]
    return value


def check_type(value, expected, name):
    # bool is a kind of int in Python, so true/false must be rejected explicitly.
    if expected == "number":
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
        type_name = "number"
    elif expected is bool:
        ok = isinstance(value, bool)
        type_name = "true/false"
    else:
        ok = isinstance(value, expected) and not isinstance(value, bool)
        type_name = expected.__name__
    if not ok:
        raise ConfigError(f"'{name}' must be of type {type_name}, got {value!r}")


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

    for path_keys, expected, minimum in REQUIRED:
        name = ".".join(path_keys)
        value = value_at(config, path_keys)
        check_type(value, expected, name)
        if minimum is not None and value < minimum:
            raise ConfigError(f"'{name}' must be at least {minimum}, got {value}")

    if config["signals"]["failed_tcp"]["threshold"] > 1:
        raise ConfigError("'signals.failed_tcp.threshold' is a share and must be at most 1")
    if config["signals"]["burst"]["percentile"] > 100:
        raise ConfigError("'signals.burst.percentile' must be at most 100")
    levels = config["severity"]
    if not levels["low"] <= levels["medium"] <= levels["high"]:
        raise ConfigError("severity levels must satisfy low <= medium <= high")

    caps = value_at(config, ("group_caps",))
    groups = {config["signals"][n]["group"] for n in SIGNAL_NAMES} | {"ml"}
    for group in sorted(groups):
        if group not in caps:
            raise ConfigError(f"'group_caps' has no entry for group '{group}'")
        check_type(caps[group], int, f"group_caps.{group}")

    # File names in config.json are relative to the folder of config.json,
    # so the program works from any current directory.
    folder = os.path.dirname(os.path.abspath(path))
    if config["blocklist_file"] != "":
        config["blocklist_file"] = os.path.join(folder, config["blocklist_file"])
    config["ml"]["model_file"] = os.path.join(folder, config["ml"]["model_file"])
    return config
