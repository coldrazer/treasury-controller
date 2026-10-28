"""P4-10: AWX_BASE_URL validation must not be fooled by userinfo/backslashes, and
loopback must not carry live credentials without an explicit TREASURY_ALLOW_HOST."""
import pytest

from config import ConfigError, validate_base_url


def test_userinfo_url_is_refused():
    with pytest.raises(ConfigError, match="userinfo"):
        validate_base_url("https://evil.example@api.sandbox.airwallex.com", {})


def test_backslash_url_is_refused():
    with pytest.raises(ConfigError, match="backslash"):
        validate_base_url("https://api.sandbox.airwallex.com\\@evil.example", {})


def test_loopback_needs_an_explicit_allow_host():
    with pytest.raises(ConfigError, match="not a known Airwallex host"):
        validate_base_url("http://127.0.0.1:9000", {})
    assert validate_base_url("http://127.0.0.1:9000", {"TREASURY_ALLOW_HOST": "127.0.0.1"}) == \
        "http://127.0.0.1:9000"


def test_sandbox_and_production_gates_unchanged():
    assert validate_base_url("https://api.sandbox.airwallex.com", {}) == \
        "https://api.sandbox.airwallex.com"
    with pytest.raises(ConfigError, match="production"):
        validate_base_url("https://api.airwallex.com", {})
    assert validate_base_url("https://api.airwallex.com", {"TREASURY_ALLOW_PRODUCTION": "1"}) == \
        "https://api.airwallex.com"
