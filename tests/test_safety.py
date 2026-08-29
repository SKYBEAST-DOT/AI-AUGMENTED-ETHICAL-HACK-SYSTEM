import pytest

from config.safety import normalize_target, validate_authorized_target


def test_normalize_target_trims_and_parses_hostname():
    assert normalize_target(" https://LOCALHOST:8080/test ") == "localhost"


def test_validate_authorized_target_blocks_public_target_without_confirmation():
    with pytest.raises(ValueError):
        validate_authorized_target("example.com", explicitly_authorized=False)


def test_validate_authorized_target_allows_public_target_with_confirmation():
    host, authorized = validate_authorized_target("example.com", explicitly_authorized=True)
    assert host == "example.com"
    assert authorized is True
