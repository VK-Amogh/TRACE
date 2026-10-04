"""Unit tests for TRACE in-app updater and version checking engine."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import trace_engine
from trace_engine.updater import (
    get_current_version,
    check_for_updates,
    render_update_banner,
    CACHE_FILE,
)


def test_get_current_version():
    ver = get_current_version()
    assert ver == trace_engine.__version__
    assert ver == "2.1.17"


def test_check_for_updates_when_newer_available(tmp_path):
    with patch("trace_engine.updater.fetch_latest_version", return_value="2.2.0"):
        info = check_for_updates(force=True)
        assert info is not None
        assert info["update_available"] is True
        assert info["latest_version"] == "2.2.0"
        assert info["current_version"] == "2.1.17"


def test_check_for_updates_when_up_to_date(tmp_path):
    with patch("trace_engine.updater.fetch_latest_version", return_value="2.1.17"):
        info = check_for_updates(force=True)
        assert info is None


def test_render_update_banner_no_crash():
    mock_info = {
        "update_available": True,
        "current_version": "2.1.8",
        "latest_version": "2.1.16",
    }
    # Ensure rendering succeeds without encoding issues on any terminal
    render_update_banner(mock_info)
