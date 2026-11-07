import os
import sys
import tempfile
import uuid

os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tempfile.gettempdir(), "ag_test_guard.db").replace("\\", "/")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-for-pytest-0123456789")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import main  # noqa: E402


@pytest.fixture()
def session():
    s = main.SessionLocal()
    yield s
    s.close()


def _make_notice(session):
    store = main.StoreModel(store_url=f"https://{uuid.uuid4().hex}.example", owner_email="o@example.com", active_skus=1)
    session.add(store)
    session.commit()
    notice = main.NoticeModel(
        store_id=store.id,
        similarity_score=95.0,
        target_infringing_url="https://bad.example/item",
        original_asset_url="https://example.com/a.jpg",
        recipient="abuse@bad.example",
        sender="legal@example.com",
        subject="s",
        body_html="<p>b</p>",
    )
    session.add(notice)
    session.commit()
    return notice


def _audit(session, notice_id):
    return session.query(main.NoticeAuditLogModel).filter_by(notice_id=notice_id).order_by(main.NoticeAuditLogModel.id).all()


def test_unconfirmed_send_is_blocked(session, monkeypatch):
    sent = []
    monkeypatch.setattr(main, "send_dmca_notice", lambda **kw: sent.append(kw) or "id")
    notice = _make_notice(session)
    with pytest.raises(main.DispatchNotAuthorized):
        main.send_notice_guarded(session, notice, api_key="k", sender_email="s", actor="admin@x", confirmed=False)
    with pytest.raises(main.DispatchNotAuthorized):
        main.send_notice_guarded(session, notice, api_key="k", sender_email="s", actor="", confirmed=True)
    assert sent == []
    assert notice.status == "PENDING"


def test_automated_send_blocked_when_setting_off(session, monkeypatch):
    sent = []
    monkeypatch.delenv("AUTO_DISPATCH_DMCA", raising=False)
    monkeypatch.setattr(main, "send_dmca_notice", lambda **kw: sent.append(kw) or "id")
    notice = _make_notice(session)
    with pytest.raises(main.DispatchNotAuthorized):
        main.send_notice_guarded(session, notice, api_key="k", sender_email="s", actor="auto-dispatch", automated=True)
    assert main.auto_dispatch_notice(session, notice.id) == "PENDING"
    assert sent == []


def test_confirmed_send_is_audited(session, monkeypatch):
    monkeypatch.setattr(main, "send_dmca_notice", lambda **kw: "msg-1")
    notice = _make_notice(session)
    msg, failure = main.send_notice_guarded(
        session, notice, api_key="k", sender_email="s", actor="admin@x", confirmed=True
    )
    assert msg == "msg-1" and failure is None
    assert notice.status == "DISPATCHED"
    rows = _audit(session, notice.id)
    assert [r.event for r in rows] == ["dispatch_confirmed", "dispatch_result"]
    assert rows[-1].status == "DISPATCHED"
    assert rows[0].user == "admin@x"
    assert rows[0].target == "https://bad.example/item"
    assert rows[0].recipient == "abuse@bad.example"
    assert rows[0].timestamp is not None


def test_automated_send_allowed_when_enabled_and_audited(session, monkeypatch):
    monkeypatch.setenv("AUTO_DISPATCH_DMCA", "true")
    monkeypatch.setattr(main, "send_dmca_notice", lambda **kw: "msg-2")
    notice = _make_notice(session)
    _, failure = main.send_notice_guarded(session, notice, api_key="k", sender_email="s", actor="auto-dispatch", automated=True)
    assert failure is None
    assert [r.event for r in _audit(session, notice.id)] == ["auto_dispatch_authorized", "dispatch_result"]


def test_second_send_is_rejected(session, monkeypatch):
    monkeypatch.setattr(main, "send_dmca_notice", lambda **kw: "m")
    notice = _make_notice(session)
    main.send_notice_guarded(session, notice, api_key="k", sender_email="s", actor="a@x", confirmed=True)
    with pytest.raises(main.DispatchConflict):
        main.send_notice_guarded(session, notice, api_key="k", sender_email="s", actor="a@x", confirmed=True)
