from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from aegis_soar.db.engine import create_app_engine, create_session_factory

DEFAULT_TEST_APP_URL = "postgresql+asyncpg://aegis_app:aegis_app_dev@localhost:5433/aegis_soar"
DEFAULT_TEST_OWNER_URL = (
    "postgresql+asyncpg://aegis_owner:aegis_owner_dev@localhost:5433/aegis_soar"
)


@pytest.fixture
async def app_engine() -> AsyncIterator[AsyncEngine]:
    """Async engine connected strictly as aegis_app (NOSUPERUSER NOBYPASSRLS)."""
    url = os.environ.get("AEGIS_APP_DATABASE_URL", DEFAULT_TEST_APP_URL)
    engine = create_app_engine(url)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
def app_session_factory(
    app_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return create_session_factory(app_engine)


@pytest.fixture
async def owner_engine() -> AsyncIterator[AsyncEngine]:
    """Privileged aegis_owner engine used ONLY for seeding/cleaning test fixtures."""
    url = os.environ.get("AEGIS_OWNER_DATABASE_URL", DEFAULT_TEST_OWNER_URL)
    engine = create_app_engine(url)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
def owner_session_factory(
    owner_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return create_session_factory(owner_engine)
