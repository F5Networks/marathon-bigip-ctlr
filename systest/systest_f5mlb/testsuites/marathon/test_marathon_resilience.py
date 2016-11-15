"""
Test suite for the behavior of the bigip-controller when Marathon goes down.
"""

import time

import pytest
import requests

from .. import utils

pytestmark = pytest.meta_suite(tags=["func", "marathon", "no_k8s"])


@pytest.meta_test(id='f5mlb-65', tags=[])
def test_no_disruptions_without_marathon(orchestration, bigip,
                                         bigip_controller):
    """
    Assert that the Big-IP configuration does not change when Marathon
    is disabled.
    """
    default_partition = utils.DEFAULT_F5MLB_PARTITION
    try:
        backend_before_config = utils.get_backend_objects(
            bigip, default_partition)
        utils.create_managed_northsouth_service(orchestration)
        utils.wait_for_bigip_controller()
        backend_before_stop = utils.get_backend_objects(
            bigip, default_partition)
        assert backend_before_stop != backend_before_config, \
            'Big-IP configuration not applied.'
        _stop_marathon()
        backend_after_stop = utils.get_backend_objects(
            bigip, default_partition)
        assert backend_after_stop == backend_before_stop, \
            'Big-IP configuration changed when Marathon stopped.'
    finally:
        _start_marathon()
        backend_after_start = utils.get_backend_objects(
            bigip, default_partition)
        assert backend_after_start == backend_after_stop, \
            'Big-IP configuration changed when Marathon restarted.'


def _stop_marathon():
    """Stop Marathon and verify that the process is gone."""
    pytest.masters_cmd('sudo service marathon stop')
    for _ in range(60):
        if not any(pytest.masters_cmd(r"ps -ef | grep '\/[m]arathon'")):
            break
        time.sleep(0.5)
    else:
        raise RuntimeError('Marathon still up after 30 seconds.')


def _start_marathon():
    """Start Marathon and verify it is serving connections."""
    pytest.masters_cmd('sudo service marathon start')
    for _ in range(120):
        try:
            if requests.get(pytest.symbols.marathon_url).ok:
                break
        except requests.ConnectionError:
            pass
        time.sleep(0.5)
    else:
        raise RuntimeError('Marathon not up after 60 seconds.')
