from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Set test DB path before any imports touch config
_test_db = tempfile.mktemp(suffix=".db")
os.environ["DB_PATH"] = _test_db
os.environ["POLICY_PATH"] = str(Path(__file__).parent / "tests" / "fixtures" / "test_policy.yaml")

from audit.db import init_db  # noqa: E402
from main import app  # noqa: E402
from policy.loader import load_policy  # noqa: E402


@pytest.fixture(scope="session")
def test_policy():
    path = Path(__file__).parent / "tests" / "fixtures" / "test_policy.yaml"
    return load_policy(str(path))


@pytest_asyncio.fixture
async def test_db():
    """Initialize a fresh test database."""
    await init_db()
    yield
    # Cleanup handled by tempfile


@pytest_asyncio.fixture
async def client(test_db):
    """Async test client for the FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
