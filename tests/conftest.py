import pytest


@pytest.fixture(autouse=True)
def no_real_ss(monkeypatch):
    """Tests never read this machine's sockets; the port tests pass their own `ss` output."""
    from themis import ports
    monkeypatch.setattr(ports, "run_ss", lambda: "")
