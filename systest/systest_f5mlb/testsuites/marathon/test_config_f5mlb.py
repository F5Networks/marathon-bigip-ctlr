"""Test suite to verify bigip-controller configuration parameters."""

import pytest
from pytest import symbols, meta_suite, meta_test

import systest_common.src as common


pytestmark = meta_suite(tags=["func", "marathon", "config"])


@pytest.fixture(scope='module', autouse=True)
def marathon(request):
    """Provide a marathon connection."""
    return common.marathon.connect(**vars(symbols))


@meta_test(id="f5mlb-27", tags=["incomplete"])
def test_bigip_controller_config_invalid_marathon_url(marathon):
    """Verify response when the 'marathon_url' value is invalid."""
    # - marathon url not provided
    # - marathon url not a valid url
    # - marathon url not a working marathon instance
    # - marathon url with no port number
    pass
