"""config.json checks and the command line: a clear message (exit code 1),
never a traceback."""

import copy
import json
import os

import pytest

from analyzer.config import ConfigError, load_config
from main import main

HERE = os.path.dirname(__file__)
BAD = os.path.join(HERE, "bad_files")
TINY_CONFIG = os.path.join(HERE, "data", "tiny_config.json")

with open(TINY_CONFIG, encoding="utf-8") as _file:
    GOOD = json.load(_file)


def write_config(tmp_path, data):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def changed(path, value):
    """A copy of the tiny config with one setting changed (value None = removed)."""
    data = copy.deepcopy(GOOD)
    target = data
    for key in path[:-1]:
        target = target[key]
    if value is None:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return data


def test_real_config_json_is_valid():
    config = load_config(os.path.join(HERE, "..", "config.json"))
    assert config["signals"]["fanout"]["threshold"] >= 1
    assert os.path.exists(config["blocklist_file"])        # path resolved next to config.json


@pytest.mark.parametrize("data, message", [
    (changed(("signals", "fanout", "threshold"), None), "signals.fanout.threshold"),
    (changed(("signals", "fanout", "threshold"), "50"), "type int"),
    (changed(("signals", "fanout", "threshold"), 0), "at least 1"),
    (changed(("signals", "failed_tcp", "threshold"), 1.5), "at most 1"),
    (changed(("signals", "burst", "percentile"), 101), "at most 100"),
    (changed(("signals", "beaconing", "min_flows"), 2), "at least 3"),
    (changed(("severity", "medium"), 9), "low <= medium <= high"),
    (changed(("ml", "enabled"), 1), "true/false"),
    (changed(("group_caps", "spread"), None), "group_caps"),
    ([1, 2, 3], "JSON object"),
])
def test_bad_config_values(tmp_path, data, message):
    with pytest.raises(ConfigError, match=message):
        load_config(write_config(tmp_path, data))


def test_broken_json_and_missing_file(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(str(path))
    with pytest.raises(ConfigError, match="not found"):
        load_config(str(tmp_path / "nope.json"))


@pytest.mark.parametrize("name", ["empty.csv", "missing_dstaddr.csv", "binary.csv", "nope.csv"])
def test_unusable_input_returns_exit_code_1(tmp_path, capsys, name):
    code = main(["--input", os.path.join(BAD, name), "--config", TINY_CONFIG, "--output", str(tmp_path)])
    assert code == 1
    assert capsys.readouterr().err.startswith("Error:")


@pytest.mark.parametrize("name", sorted(os.listdir(BAD)))
def test_every_bad_file_is_handled_without_crash(tmp_path, name):
    # Robustness check: every file must end with exit code 0 or 1, never an exception.
    code = main(["--input", os.path.join(BAD, name), "--config", TINY_CONFIG, "--output", str(tmp_path)])
    assert code in (0, 1)


def test_header_only_file_writes_outputs(tmp_path):
    code = main(["--input", os.path.join(BAD, "header_only.csv"), "--config", TINY_CONFIG,
                 "--output", str(tmp_path)])
    assert code == 0
    assert "No valid flows" in (tmp_path / "summary.txt").read_text(encoding="utf-8")
    assert (tmp_path / "top_fanout.png").exists()


def test_missing_blocklist_file_is_a_clear_error(tmp_path, capsys):
    config = write_config(tmp_path, changed(("blocklist_file",), "missing_list.txt"))
    code = main(["--input", os.path.join(BAD, "single_flow.csv"), "--config", config,
                 "--output", str(tmp_path / "out")])
    assert code == 1
    assert "blocklist_file" in capsys.readouterr().err


def test_ml_without_model_file_is_a_clear_error(tmp_path, capsys):
    data = changed(("ml", "model_file"), "no_model.pkl")
    data["blocklist_file"] = ""
    config = write_config(tmp_path, data)
    code = main(["--input", os.path.join(BAD, "single_flow.csv"), "--config", config,
                 "--output", str(tmp_path / "out"), "--ml"])
    assert code == 1
    assert "train_model.py" in capsys.readouterr().err


def test_ml_without_scikit_learn_is_a_clear_error(tmp_path, capsys, monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_sklearn(name, *args, **kwargs):
        if name.startswith("sklearn") or name == "analyzer.ml_model":
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_sklearn)
    code = main(["--input", os.path.join(BAD, "single_flow.csv"), "--config", TINY_CONFIG,
                 "--output", str(tmp_path), "--ml"])
    assert code == 1
    assert "scikit-learn" in capsys.readouterr().err


def test_file_without_state_and_time_columns(tmp_path):
    data = tmp_path / "minimal.csv"
    data.write_text("SrcAddr,DstAddr\n10.0.0.1,10.0.0.100\n10.0.0.1,10.0.0.101\n"
                    "10.0.0.1,10.0.0.103\n", encoding="utf-8")
    code = main(["--input", str(data), "--config", TINY_CONFIG, "--output", str(tmp_path / "out")])
    assert code == 0
    summary = (tmp_path / "out" / "summary.txt").read_text(encoding="utf-8")
    assert "no State column, failed_tcp cannot fire" in summary
    assert "no StartTime column, port_scan, burst and beaconing cannot fire" in summary
    assert "No Label column" in summary
    assert "10.0.0.1 [medium, score 2]: fanout" in summary
