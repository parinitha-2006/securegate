import pytest
from app import create_app


@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True, "DATABASE": str(tmp_path / "t.db"), "RATE_LIMIT": 1000})


@pytest.fixture
def client(app):
    return app.test_client()
