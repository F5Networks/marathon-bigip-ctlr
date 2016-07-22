"""Test suite to verify f5mlb configuration parameters."""


from pytest import meta_suite, meta_test


pytestmark = meta_suite(tags=["func", "marathon", "config"])


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_marathon(marathon):
    """Verify response when the 'marathon' arg is invalid."""
    # - marathon url not provided
    # - marathon url not a valid url
    # - marathon url not a working marathon instance
    # - marathon url with no port number
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_partition(marathon):
    """Verify response when the 'partition' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_hostname(marathon):
    """Verify response when the bigip 'hostname' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_creds(marathon):
    """Verify response when the bigip user credentials are invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_auth_file(marathon):
    """Verify response when the 'marathon auth file' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_auth_file(marathon):
    """Verify response when the 'marathon auth file' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_health_check(marathon):
    """Verify response when the 'health-check' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_health_check(marathon):
    """Verify response when the 'health-check' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_syslog_socket(marathon):
    """Verify response when the 'syslog-socket' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_syslog_socket(marathon):
    """Verify response when the 'syslog-socket' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_log_format(marathon):
    """Verify response when the 'log-format' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_log_format(marathon):
    """Verify response when the 'log-format' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_listening(marathon):
    """Verify response when the 'listening' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_listening(marathon):
    """Verify response when the 'listening' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_callback_url(marathon):
    """Verify response when the 'callback-url' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_callback_url(marathon):
    """Verify response when the 'callback-url' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_sse(marathon):
    """Verify response when the 'sse' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_sse(marathon):
    """Verify response when the 'sse' arg is invalid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_conflict_sse_listening(marathon):
    """Verify response when both 'sse' and' listening' are specified."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_valid_sse_timeout(marathon):
    """Verify response when the 'sse-timeout' arg is valid."""
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_f5mlb_config_invalid_sse_timeout(marathon):
    """Verify response when the 'sse-timeout' arg is invalid."""
    pass
