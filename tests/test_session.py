"""Tests for session management."""

from unittest.mock import patch

import pytest

from voidfreq.core.session import Phase, SessionData, SessionManager


@pytest.fixture
def tmp_session_dir(tmp_path):
    with patch("voidfreq.core.session.SESSION_DIR", str(tmp_path)):
        yield tmp_path


@pytest.fixture
def mgr(tmp_session_dir):
    return SessionManager()


def test_create_session(mgr, tmp_session_dir):
    session = mgr.create(
        name="test_session",
        target_bssid="AA:BB:CC:DD:EE:FF",
        target_channel=6,
        stealth_level="high",
    )

    assert session.name == "test_session"
    assert session.target_bssid == "AA:BB:CC:DD:EE:FF"
    assert session.target_channel == 6
    assert session.phase == Phase.INIT.value

    path = tmp_session_dir / f"{session.id}.json"
    assert path.exists()


def test_load_session(mgr, tmp_session_dir):
    session = mgr.create(name="load_test", target_bssid="11:22:33:44:55:66")
    loaded = mgr.load(session.id)

    assert loaded is not None
    assert loaded.name == "load_test"
    assert loaded.target_bssid == "11:22:33:44:55:66"


def test_load_nonexistent(mgr):
    result = mgr.load("nonexistent_session")
    assert result is None


def test_update_phase(mgr):
    session = mgr.create(name="phase_test")

    mgr.update_phase(session, Phase.RECON, recon_data={"aps": 3})
    assert session.phase == Phase.RECON.value
    assert session.recon_data == {"aps": 3}

    mgr.update_phase(session, Phase.CAPTURE, captured_file="/tmp/cap.pcap")
    assert session.phase == Phase.CAPTURE.value
    assert session.captured_file == "/tmp/cap.pcap"


def test_delete_session(mgr, tmp_session_dir):
    session = mgr.create(name="delete_test")
    path = tmp_session_dir / f"{session.id}.json"
    assert path.exists()

    result = mgr.delete(session.id)
    assert result is True
    assert not path.exists()


def test_delete_nonexistent(mgr):
    result = mgr.delete("nonexistent")
    assert result is False


def test_list_sessions(mgr):
    mgr.create(name="list_test_1")
    mgr.create(name="list_test_2")

    sessions = mgr.list_sessions()
    names = {s.name for s in sessions}
    assert "list_test_1" in names
    assert "list_test_2" in names


def test_add_note(mgr):
    session = mgr.create(name="note_test")
    mgr.add_note(session, "Found open port 80")

    assert len(session.notes) == 1
    assert "Found open port 80" in session.notes[0]


def test_session_data_fields():
    data = SessionData(
        id="test_id",
        name="test",
        created="2025-01-01T00:00:00",
        updated="2025-01-01T00:00:00",
    )
    assert data.phase == Phase.INIT.value
    assert data.cracked_password is None
    assert data.notes == []
    assert data.log == []


def test_corrupt_session_file(tmp_session_dir, mgr):
    bad_file = tmp_session_dir / "corrupt.json"
    bad_file.write_text("not valid json {{{")

    sessions = mgr.list_sessions()
    assert not any(s.id == "corrupt" for s in sessions)
