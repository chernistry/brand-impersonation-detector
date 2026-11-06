import pytest


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path_factory, monkeypatch):
    """Every test gets its own $BID_DATA_DIR, so runtime state (stores, caches, the
    governance journal) never leaks between tests or into the working tree."""
    monkeypatch.setenv("BID_DATA_DIR", str(tmp_path_factory.mktemp("bid-data")))
