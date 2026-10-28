
import pytest

from app.core.security import require_api_key
from app.main import app


@pytest.fixture(autouse=True)
def override_api_key_authentication(request):
    # Keep authentication enabled in dedicated authentication tests.
    if request.node.path.name == "test_authentication.py":
        yield
        return

    previous_override = app.dependency_overrides.get(require_api_key)
    app.dependency_overrides[require_api_key] = lambda: None

    yield

    if previous_override is None:
        app.dependency_overrides.pop(require_api_key, None)
    else:
        app.dependency_overrides[require_api_key] = previous_override
