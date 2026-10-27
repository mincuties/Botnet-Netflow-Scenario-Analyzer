"""Tests for the small text-to-value helpers in flow.py."""

import pytest

from analyzer.flow import Flow, parse_count, parse_port, parse_time


def test_parse_count_normal_and_float_written_number():
    assert parse_count("214", "TotBytes") == 214
    assert parse_count(" 100.0 ", "TotBytes") == 100


@pytest.mark.parametrize("bad", ["", "abc", "-5", "1.5"])
def test_parse_count_rejects_bad_values(bad):
    with pytest.raises(ValueError):
        parse_count(bad, "TotBytes")


def test_parse_port_decimal_hex_and_bad():
    assert parse_port("53") == 53
    assert parse_port("0x0008") == 8      # CTU-13 writes ICMP ports in hex
    assert parse_port("08") == 8          # leading zero
    assert parse_port("") is None
    assert parse_port("xyz") is None
    assert parse_port("99999") is None    # above 65535


def test_parse_time_good_and_bad():
    fmt = "%Y/%m/%d %H:%M:%S.%f"
    assert parse_time("2011/08/16 10:01:46.972101", fmt).second == 46
    assert parse_time("not-a-date", fmt) is None
    assert parse_time("", fmt) is None


def test_label_from_botnet_vs_to_botnet():
    # "To-Botnet" means the bot is the DESTINATION, so the source is not a bot.
    assert Flow("a", "b", label="flow=From-Botnet-V48-1").is_from_botnet()
    assert not Flow("a", "b", label="flow=To-Botnet-V48-1").is_from_botnet()
    assert Flow("a", "b", label="flow=From-Normal-V48").is_from_normal()
