"""Tests for HeavenlyEyes utilities."""

from heavenlyeyes.core.utils import is_valid_domain, is_valid_email, is_valid_ip


def test_valid_domain():
    assert is_valid_domain("example.com")
    assert is_valid_domain("sub.example.com")
    assert not is_valid_domain("not a domain")
    assert not is_valid_domain("")


def test_valid_email():
    assert is_valid_email("test@example.com")
    assert is_valid_email("user.name+tag@domain.co")
    assert not is_valid_email("notanemail")
    assert not is_valid_email("@domain.com")


def test_valid_ip():
    assert is_valid_ip("192.168.1.1")
    assert is_valid_ip("8.8.8.8")
    assert not is_valid_ip("999.999.999.999")
    assert not is_valid_ip("abc.def.ghi.jkl")
