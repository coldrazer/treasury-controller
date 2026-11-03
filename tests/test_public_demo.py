"""Public exposure: per-visitor sandboxes, lockout-proof demo sign-in, proxy origin and cookie flags.

Runs the same dashboard handler with TREASURY_PUBLIC_DEMO / TREASURY_PUBLIC_ORIGIN switched on.
"""
from __future__ import annotations

import importlib
import json
import re
from http.server import HTTPServer

import pytest

from test_audit_regressions import issued_cookie, ui_request

PUBLIC = "https://demo.example.com"
SAM = ("sam.treasury", "fx-approve-42")


@pytest.fixture
def public(tmp_path, monkeypatch):
    monkeypatch.setenv("TREASURY_STATE_DIR", str(tmp_path / "ui"))
    monkeypatch.setenv("LLM_PROVIDER", "rules")
    module = importlib.import_module("webui")
    monkeypatch.setattr(module, "PUBLIC_DEMO", True)
    monkeypatch.setattr(module, "PUBLIC_ORIGIN", PUBLIC)
    monkeypatch.setattr(module, "PUBLIC_HOST", "demo.example.com")
    monkeypatch.setattr(module, "SECURE_COOKIE", True)
    monkeypatch.setattr(module, "MAX_DEMOS", 2)
    monkeypatch.setattr(module, "_PUBLIC_PAGE", None)
    server = HTTPServer(("127.0.0.1", 0), module.Handler)
    server.session = None
    server.sessions = module.Sessions()
    server.timeout = 5
    yield module, server
    for s in list(server.sessions._by_token.values()):
        server.sessions._retire(s)
    server.server_close()
    module._PUBLIC_PAGE = None


class Visitor:
    def __init__(self, server, origin=PUBLIC, host="demo.example.com"):
        self.server, self.origin, self.host = server, origin, host
        self.cookie = self.csrf = None

    def headers(self):
        h = {"Host": self.host, "Origin": self.origin, "Content-Type": "application/json"}
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        if self.cookie:
            h["Cookie"] = self.cookie
        return h

    def load(self):
        r = ui_request(self.server, "/", method="GET", headers=self.headers())
        if issued_cookie(r):
            self.cookie = issued_cookie(r)
        self.csrf = re.search(rb'name="csrf" content="([0-9a-f]+)"', r["body"]).group(1).decode()
        return r

    def post(self, path, body):
        return ui_request(self.server, path, headers=self.headers(), body=body)

    def sign_in(self, who=SAM):
        if not self.csrf:
            self.load()
        r = self.post("/api/login", {"approver_id": who[0], "pin": who[1]})
        if r["status"] == 200:
            self.cookie = issued_cookie(r)
            self.load()
        return r

    def state(self):
        return json.loads(ui_request(self.server, "/api/state", method="GET", headers=self.headers())["body"])


def test_wrong_pins_never_lock_the_public_demo_accounts(public):
    _, server = public
    stranger = Visitor(server)
    for _ in range(12):
        assert stranger.sign_in((SAM[0], "wrong-guess-1"))["status"] == 403
    assert server.sessions.live_demos() == 0  # failed guesses boot nothing
    assert Visitor(server).sign_in()["status"] == 200


def test_each_visitor_gets_a_private_sandbox(public):
    _, server = public
    a, b = Visitor(server), Visitor(server)
    assert a.sign_in()["status"] == 200 and b.sign_in()["status"] == 200
    assert a.post("/api/act1", {})["status"] == 200
    assert a.state()["act"] == 1 and b.state()["act"] == 0
    assert a.state()["cycle"] != b.state()["cycle"]
    reset = b.post("/api/reset", {"confirm": True})
    assert reset["status"] == 200
    assert a.state()["act"] == 1  # b's reset does not touch a


def test_capacity_is_enforced(public):
    _, server = public
    assert Visitor(server).sign_in()["status"] == 200
    assert Visitor(server).sign_in()["status"] == 200
    third = Visitor(server).sign_in()
    assert third["status"] == 503


def test_wrong_pin_on_a_card_is_refused_before_the_store(public):
    _, server = public
    v = Visitor(server)
    v.sign_in()
    for act in (1, 2):
        assert v.post(f"/api/act{act}", {})["status"] == 200
    cards = v.state()["pending_approvals"]
    assert cards, "act 2 should leave a card to sign"
    card = cards[0]
    for _ in range(6):
        r = v.post("/api/sign", {"approval_id": card["id"], "approver_id": SAM[0], "pin": "nope-nope-1",
                                 "confirm_code": card["code"], "decision": "approve"})
        assert r["status"] == 403
    assert v.sign_in()["status"] == 200  # still not locked


def test_proxy_origin_cookie_and_headers(public):
    _, server = public
    v = Visitor(server)
    page = v.load()
    assert "Secure" in page["headers"]["Set-Cookie"]
    assert page["headers"]["Strict-Transport-Security"].startswith("max-age=")
    assert b"fx-approve-42" in page["body"]
    evil = Visitor(server, origin="https://evil.example")
    evil.load()
    assert evil.post("/api/login", {"approver_id": SAM[0], "pin": SAM[1]})["status"] == 403
    plain = Visitor(server, origin="http://demo.example.com")
    plain.load()
    assert plain.post("/api/login", {"approver_id": SAM[0], "pin": SAM[1]})["status"] == 403
    spoof = ui_request(server, "/", method="GET", headers={"Host": "evil.example"})
    assert spoof["status"] == 403


def test_closed_sandboxes_leave_no_files(public, tmp_path):
    _, server = public
    v = Visitor(server)
    v.sign_in()
    mock_dir = tmp_path / "ui" / "mock"
    assert list(mock_dir.glob("*.db"))
    v.post("/api/logout", {})
    assert not list(mock_dir.glob("*.db"))
