from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from guardian.config import get_settings


class Base(DeclarativeBase):
    pass


def build_engine(database_url: str):  # type: ignore[no-untyped-def]
    options: dict[str, object] = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
        if database_url in {"sqlite://", "sqlite:///:memory:"}:
            options["poolclass"] = StaticPool
        else:
            database_path = make_url(database_url).database
            if database_path:
                Path(database_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    return create_engine(database_url, **options)


def _configured_database_url() -> str:
    return get_settings().database_url


engine = build_engine(_configured_database_url())
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
