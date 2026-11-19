import pytest
from alert_scanner.web import InvalidAddress, normalize_address


@pytest.mark.parametrize("raw, expected", [
    ("przyklad.pl", "http://przyklad.pl"),
    ("  https://moja-strona.com/sklep  ", "https://moja-strona.com/sklep"),
    ("localhost:3000", "http://host.docker.internal:3000"),
    ("http://127.0.0.1:8080/app", "http://host.docker.internal:8080/app"),
])
def test_normalize_address(raw, expected):
    assert normalize_address(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "ftp://example.com", "http://", "example.com:99999"])
def test_normalize_address_rejects_bad_input(raw):
    with pytest.raises(InvalidAddress):
        normalize_address(raw)
