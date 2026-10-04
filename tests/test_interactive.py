"""Unit and integration tests for the interactive story-driven TUI interface."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from trace_engine.interactive import render_big_banner, run_interactive_story


def test_render_big_banner():
    """Verify that big pixel TRACE banner renders without error."""
    # Should execute cleanly without raising
    render_big_banner(animated=False)


@patch("trace_engine.interactive.Prompt.ask")
@patch("trace_engine.interactive.Confirm.ask")
def test_interactive_story_all_tests_flow(mock_confirm, mock_prompt, tmp_path):
    """Verify step-by-step interactive story mode flow for all tests."""
    # Simulate user inputs:
    # 1. Mission Select: Option 1 (Full Security Audit - Default)
    # 2. Repo path: "testbed_hardcore"
    # 3. Target URL: "http://127.0.0.1:18080"
    # 4. Post-audit export: Option 3 (Finish session)
    mock_prompt.side_effect = [
        "1",                      # Mission option
        "testbed_hardcore",       # Target repo
        "http://127.0.0.1:18080", # Target URL
        "n",                      # Self-healing decline
        "3",                      # Finish session
    ]
    mock_confirm.return_value = False

    # Execute interactive story
    run_interactive_story()
