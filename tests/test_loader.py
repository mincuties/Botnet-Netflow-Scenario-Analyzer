"""Tests for loader.py: one test per edge case in tests/bad_files/."""

import os

import pytest

from analyzer.loader import LoaderError, load_flows

BAD = os.path.join(os.path.dirname(__file__), "bad_files")


def path(name):
    return os.path.join(BAD, name)


def test_empty_file_gives_clear_error():
    with pytest.raises(LoaderError, match="empty"):
        load_flows(path("empty.csv"))


def test_missing_file_gives_clear_error():
    with pytest.raises(LoaderError, match="not found"):
        load_flows(path("does_not_exist.csv"))


def test_binary_file_gives_clear_error():
    with pytest.raises(LoaderError, match="UTF-8"):
        load_flows(path("binary.csv"))


def test_missing_required_column_names_the_column():
    with pytest.raises(LoaderError, match="DstAddr"):
        load_flows(path("missing_dstaddr.csv"))


def test_header_only_gives_zero_flows():
    result = load_flows(path("header_only.csv"))
    assert result.rows_read == 0
    assert result.flows == []


def test_missing_optional_label_column_still_works():
    result = load_flows(path("no_label.csv"))
    assert len(result.flows) == 2
    assert "Label" in result.missing_optional


def test_renamed_and_reordered_columns_are_recognised():
    # Header: "Label, dst_ip ,SRCADDR,Src_Bytes,TotBytes"
    result = load_flows(path("renamed_reordered.csv"))
    first = result.flows[0]
    assert first.src_ip == "10.0.0.1"
    assert first.dst_ip == "10.0.0.100"
    assert first.src_bytes == 60
    assert first.total_bytes == 100
    assert first.is_from_botnet()


def test_extra_column_is_ignored():
    result = load_flows(path("extra_column.csv"))
    assert len(result.flows) == 2
    assert "Country" in result.ignored_columns


def test_bom_at_start_of_file():
    result = load_flows(path("bom.csv"))
    assert "StartTime" not in result.missing_optional
    assert result.flows[0].start_time is not None


def test_semicolon_separator_is_detected():
    result = load_flows(path("semicolon.csv"))
    assert result.delimiter == ";"
    assert len(result.flows) == 1


def test_bad_values_are_skipped_and_counted_by_reason():
    result = load_flows(path("bad_values.csv"))
    assert result.rows_read == 6
    assert len(result.flows) == 1              # only "100.0" is acceptable
    assert result.skipped["TotBytes is negative"] == 1
    assert result.skipped["SrcBytes is not a number"] == 1
    assert result.skipped["SrcBytes is not a whole number"] == 1
    assert result.skipped["TotBytes is empty"] == 1
    assert result.skipped["empty DstAddr"] == 1


def test_wrong_field_count_rows_are_skipped_blank_lines_ignored():
    result = load_flows(path("wrong_field_count.csv"))
    assert result.rows_read == 4               # the blank line is not counted
    assert len(result.flows) == 2
    assert sum(result.skipped.values()) == 2


def test_bad_time_and_port_keep_the_row():
    result = load_flows(path("bad_time_and_port.csv"))
    flow = result.flows[0]
    assert flow.start_time is None
    assert flow.dst_port is None
