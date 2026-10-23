"""Shared pytest fixtures and import shims for the Lambda unit tests.

The Lambda modules read required environment variables and create boto3 clients
at import time. The tests exercise pure functions (the SQL guard, the authorizer
policy logic) and must not reach AWS, so this conftest sets placeholder
environment variables and stubs boto3 before the modules are imported.
"""
import os
import sys
import types
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_API_HANDLER_DIR = _REPO_ROOT / "lambda" / "api-handler"
_AUTHORIZER_DIR = _REPO_ROOT / "lambda" / "authorizer"


def _stub_boto3() -> None:
    """Install a no-op boto3 so `boto3.client(...)` at module scope succeeds.

    Replace unconditionally: if the real boto3 is already installed (it is a
    declared Lambda dependency), an early return would leave it in place and the
    Lambda modules would build live AWS clients at import. The stub must win
    regardless of load order.
    """
    boto3_stub = types.ModuleType("boto3")
    boto3_stub.client = lambda *_args, **_kwargs: object()
    sys.modules["boto3"] = boto3_stub


def _stub_jwt() -> None:
    """Install a minimal PyJWT stub so the authorizer module imports.

    The authorizer builds a PyJWKClient at module scope. The tests cover the
    fail-closed path (missing methodArn) and the policy builder, neither of
    which decodes a real token, so a stub avoids the PyJWT + cryptography
    dependency for running the suite.

    Replace unconditionally: PyJWT is a declared authorizer dependency, so an
    early return when it is installed would leave the real client in place and
    PyJWKClient would make a live JWKS request at import time.
    """
    jwt_stub = types.ModuleType("jwt")
    jwt_stub.decode = lambda *_args, **_kwargs: {}

    class _PyJWKClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get_signing_key_from_jwt(self, *_args, **_kwargs):
            raise RuntimeError("stub: no signing key")

    jwt_stub.PyJWKClient = _PyJWKClient
    sys.modules["jwt"] = jwt_stub


def _set_api_handler_env() -> None:
    os.environ.setdefault("MODEL_ID", "amazon.nova-pro-v1:0")
    os.environ.setdefault("ATHENA_WORKGROUP", "test-workgroup")
    os.environ.setdefault("GLUE_CATALOG_NAME", "test-catalog")
    os.environ.setdefault("GLUE_DATABASE", "test-db")


def _set_authorizer_env() -> None:
    os.environ.setdefault("OIDC_ISSUER", "https://issuer.example.com/")
    os.environ.setdefault("OIDC_AUDIENCE", "test-audience")
    os.environ.setdefault("REQUIRED_GROUP", "security-analysts")
    # Give an explicit JWKS URI so the authorizer module does not attempt OIDC
    # discovery over the network at import time.
    os.environ.setdefault("OIDC_JWKS_URI", "https://issuer.example.com/jwks.json")


# Make both Lambda source directories importable by their module name.
sys.path.insert(0, str(_API_HANDLER_DIR))
sys.path.insert(0, str(_AUTHORIZER_DIR))

_stub_boto3()
_stub_jwt()
_set_api_handler_env()
_set_authorizer_env()
