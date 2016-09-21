"""Test suite to verify f5mlb configuration parameters."""


from pytest import meta_suite, meta_test


pytestmark = meta_suite(tags=["func", "marathon", "k8s", "config"])


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_partition(orchestration):
    """Verify response when the 'partition' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_hostname(orchestration):
    """Verify response when the bigip 'hostname' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_creds(orchestration):
    """Verify response when the bigip user credentials are invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_health_check(orchestration):
    """Verify response when the 'health-check' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_health_check(orchestration):
    """Verify response when the 'health-check' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_syslog_socket(orchestration):
    """Verify response when the 'syslog-socket' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_syslog_socket(orchestration):
    """Verify response when the 'syslog-socket' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_log_format(orchestration):
    """Verify response when the 'log-format' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_log_format(orchestration):
    """Verify response when the 'log-format' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_listening(orchestration):
    """Verify response when the 'listening' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_listening(orchestration):
    """Verify response when the 'listening' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_callback_url(orchestration):
    """Verify response when the 'callback-url' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_callback_url(orchestration):
    """Verify response when the 'callback-url' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_sse(orchestration):
    """Verify response when the 'sse' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_sse(orchestration):
    """Verify response when the 'sse' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_conflict_sse_listening(orchestration):
    """Verify response when both 'sse' and' listening' are specified."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_sse_timeout(orchestration):
    """Verify response when the 'sse-timeout' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_sse_timeout(orchestration):
    """Verify response when the 'sse-timeout' arg is invalid."""
    pass
