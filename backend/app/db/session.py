from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings


def _engine_kwargs() -> dict:
    url = settings.get_database_url()
    kwargs = {
        "pool_pre_ping": True,
        "echo": settings.DEBUG,
    }
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        # SQLite does not support pool_pre_ping the same way as network DBs;
        # SQLAlchemy handles it, but disabling is cleaner for local demo DBs.
        kwargs["pool_pre_ping"] = False
    return kwargs


engine = create_engine(settings.get_database_url(), **_engine_kwargs())

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency for obtaining a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
