"""Owner-controlled first administrator provisioning.

This is an out-of-band command-line helper, not an HTTP endpoint. It does not
start a server, create accounts automatically, or embed credentials. Run it only
from a trusted owner-controlled environment after the database schema exists.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import settings  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.models.user import UserRole  # noqa: E402
from app.services.user_service import create_user  # noqa: E402


def _owner_password() -> str:
    """Read the password at run time; never print or persist it here."""
    password = os.environ.get("APISENTRY_NEW_ADMIN_PASSWORD", "")
    if not password:
        password = getpass.getpass("New administrator password: ")
    if not password:
        raise SystemExit("A non-empty administrator password is required")
    return password


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision the first administrator through the trusted service layer."
    )
    parser.add_argument("--email", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument(
        "--confirm-production",
        action="store_true",
        help="Required when ENVIRONMENT=production.",
    )
    args = parser.parse_args()

    if settings.is_production and not args.confirm_production:
        raise SystemExit(
            "Refusing to provision an administrator in production without --confirm-production"
        )

    password_hash_input = _owner_password()
    from app.core.security import hash_password

    password_hash = hash_password(password_hash_input)

    db = SessionLocal()
    try:
        user = create_user(
            db=db,
            email=args.email,
            username=args.username,
            password_hash=password_hash,
            role=UserRole.ADMIN.value,
            is_active=True,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    finally:
        db.close()

    print(f"Provisioned administrator id={user.id} username={user.username}")


if __name__ == "__main__":
    main()
