"""The program must give a clear message (exit code 1), never a traceback."""

import json
import os

import pytest

from analyzer.config import ConfigError, load_config
from main import main

HERE = os.path.dirname(__file__)
BAD = os.path.join(HERE, "bad_files")
TINY_CONFIG = os.path.join(HERE, "data", "tiny_config.json")


def write_config(tmp_path, data):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_real_config_json_is_valid():
    config = load_config(os.path.join(HERE, "..", "config.json"))
    assert config["fanout_min_destinations"] >= 1


@pytest.mark.parametrize("data, message", [
    ({"upload_min_src_bytes": 1, "time_format": "%Y", "plot_top_n": 5}, "fanout_min_destinations"),
    ({"fanout_min_destinations": "50", "upload_min_src_bytes": 1, "time_format": "%Y", "plot_top_n": 5}, "type int"),
    ({"fanout_min_destinations": 0, "upload_min_src_bytes": 1, "time_format": "%Y", "plot_top_n": 5}, "at least 1"),
    ([1, 2, 3], "JSON object"),
])
def test_bad_config_values(tmp_path, data, message):
    with pytest.raises(ConfigError, match=message):
        load_config(write_config(tmp_path, data))


def test_broken_json(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(str(path))


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
