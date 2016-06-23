"""Test suite to verify managed service configuration parameters."""


from pytest import meta_suite, meta_test
from pytest import symbols

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "config"])


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_svc_config_invalid_partition(marathon):
    """Verify response when the 'F5_PARTITION' label is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_svc_config_invalid_bind_addr(marathon):
    """Verify response when the 'F5_{n}_BIND_ADDR' label is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_svc_config_invalid_port(marathon):
    """Verify response when the 'F5_{n}_PORT' label is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_svc_config_valid_mode(marathon):
    """Verify response when the 'F5_{n}_MODE' label is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_svc_config_invalid_mode(marathon):
    """Verify response when the 'F5_{n}_MODE' label is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_svc_config_valid_balance(marathon):
    """Verify response when the 'F5_{n}_BALANCE' label is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_svc_config_invalid_balance(marathon):
    """Verify response when the 'F5_{n}_BALANCE' label is invalid."""
    pass
