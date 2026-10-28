"""P4-11: list_transfers must page through results, not read only the first page."""
from airwallex_client import AirwallexClient


def _client(pages):
    client = AirwallexClient.__new__(AirwallexClient)
    seen = []

    def fake_request(method, path, params=None, **_kw):
        seen.append(params)
        return pages[params["page_num"]]

    client.request = fake_request
    return client, seen


def test_list_transfers_follows_has_more():
    client, seen = _client([
        {"items": [{"id": "t1", "transfer_currency": "EUR"}], "has_more": True},
        {"items": [{"id": "t2", "transfer_currency": "EUR"}], "has_more": False},
    ])
    out = client.list_transfers(transfer_currency="EUR")
    assert [t["id"] for t in out] == ["t1", "t2"]
    assert [p["page_num"] for p in seen] == [0, 1]


def test_list_transfers_stops_when_the_server_never_stops():
    client, seen = _client([{"items": [{"id": f"t{i}"}], "has_more": True} for i in range(60)])
    out = client.list_transfers()
    assert len(seen) == 50  # bounded, not infinite
    assert len(out) == 50
