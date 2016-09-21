"""Test suite to verify f5mlb configuration parameters."""

import pytest
from pytest import symbols, meta_suite, meta_test

import systest_common.src as common


pytestmark = meta_suite(tags=["func", "marathon", "config"])


@pytest.fixture(scope='module', autouse=True)
def marathon(request):
    """Provide a marathon connection."""
    return common.marathon.connect(**vars(symbols))


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_marathon(marathon):
    """Verify response when the 'marathon' arg is invalid."""
    # - marathon url not provided
    # - marathon url not a valid url
    # - marathon url not a working marathon instance
    # - marathon url with no port number
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_auth_file(marathon):
    """Verify response when the 'marathon auth file' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_auth_file(marathon):
    """Verify response when the 'marathon auth file' arg is invalid."""
    pass
