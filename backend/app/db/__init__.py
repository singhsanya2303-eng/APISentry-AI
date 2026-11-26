"""Database package exposing SQLAlchemy engine, session factory, base model, DB dependency, and table initializer."""
from importlib import import_module

from app.db.base import Base

__all__ = ["Base", "engine", "SessionLocal", "get_db", "init_db"]

# These exports are resolved on first access so that importing app.db.base
# (which every ORM model does) does not initialize settings or create a global
# engine as an import side effect.
_LAZY_EXPORTS = {
    "engine": ("app.db.session", "engine"),
    "SessionLocal": ("app.db.session", "SessionLocal"),
    "get_db": ("app.db.session", "get_db"),
    "init_db": ("app.db.init_db", "init_db"),
}


def __getattr__(name):
    try:
        module_name, attribute = _LAZY_EXPORTS[name]
    except KeyError:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        ) from None
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value
