"""Tests for dependency checker."""

from unittest.mock import patch

from voidfreq.utils.deps import OPTIONAL, REQUIRED, check_dependencies


@patch("voidfreq.utils.deps.shutil.which")
def test_all_present(mock_which):
    mock_which.return_value = "/usr/bin/mock"
    missing_req, missing_opt = check_dependencies()
    assert missing_req == []
    assert missing_opt == []


@patch("voidfreq.utils.deps.shutil.which")
def test_missing_required(mock_which):
    def which_side_effect(tool):
        if tool in REQUIRED:
            return None
        return "/usr/bin/mock"

    mock_which.side_effect = which_side_effect
    missing_req, missing_opt = check_dependencies()
    assert set(missing_req) == set(REQUIRED.keys())
    assert missing_opt == []


@patch("voidfreq.utils.deps.shutil.which")
def test_missing_optional(mock_which):
    def which_side_effect(tool):
        if tool in OPTIONAL:
            return None
        return "/usr/bin/mock"

    mock_which.side_effect = which_side_effect
    missing_req, missing_opt = check_dependencies()
    assert missing_req == []
    assert set(missing_opt) == set(OPTIONAL.keys())


@patch("voidfreq.utils.deps.shutil.which")
def test_all_missing(mock_which):
    mock_which.return_value = None
    missing_req, missing_opt = check_dependencies()
    assert len(missing_req) == len(REQUIRED)
    assert len(missing_opt) == len(OPTIONAL)
