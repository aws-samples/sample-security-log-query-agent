"""API Gateway TOKEN authorizer - validates an OIDC JWT and gates on a group claim.

Generalized, IdP-agnostic reference implementation. Works with any standards
compliant OIDC provider that publishes a JWKS document, for example:

  * Microsoft Entra ID  (groups appear in the "groups" claim; app roles in "roles")
  * Amazon Cognito      (groups appear in the "cognito:groups" claim)
  * Okta                (groups appear in a "groups" claim you map in the auth server)

Behaviour:
  1. Extract the bearer token from the API Gateway TOKEN-authorizer event.
  2. Resolve the issuer's signing key via JWKS (PyJWT PyJWKClient).
  3. Verify signature (RS256), issuer, audience, and expiry.
  4. Require the caller to hold REQUIRED_GROUP in one of the common group claims.
  5. Return an IAM Allow/Deny policy to API Gateway. The gateway caches the
     result per-token (see authorizer resultsCacheTtl in the stack).

Configuration (all via environment variables):
  OIDC_ISSUER     (required)  e.g. https://login.microsoftonline.com/<tenant>/v2.0
  OIDC_AUDIENCE   (required)  the API/app client id the token is minted for
  REQUIRED_GROUP  (required)  group/role value the caller must hold
  OIDC_JWKS_URI   (optional)  explicit JWKS URL; if unset it is derived from the
                              issuer's /.well-known/openid-configuration, falling
                              back to <issuer>/.well-known/jwks.json

Packaging: bundle PyJWT + cryptography as a Lambda layer or in the function
artifact at deploy time (see requirements.txt in this directory).
"""
import json
import os
import urllib.request

import jwt  # PyJWT
from jwt import PyJWKClient

OIDC_ISSUER = os.environ["OIDC_ISSUER"].rstrip("/")
OIDC_AUDIENCE = os.environ["OIDC_AUDIENCE"]
REQUIRED_GROUP = os.environ["REQUIRED_GROUP"].strip()

# Claims that different IdPs use to carry group/role membership.
_GROUP_CLAIMS = ("groups", "roles", "cognito:groups")

# Resource used on a Deny when no methodArn is present. API Gateway requires a
# non-empty resource string; this sentinel grants nothing and avoids a "*".
# Partition-neutral (arn:*) so it is correct in commercial and GovCloud alike.
DENY_RESOURCE = "arn:*:execute-api:*:*:*/*/*/deny"


def _resolve_jwks_uri() -> str:
    """Return the JWKS URI: explicit env, else OIDC discovery, else the conventional path."""
    explicit = os.environ.get("OIDC_JWKS_URI", "").strip()
    if explicit:
        return explicit

    discovery_url = f"{OIDC_ISSUER}/.well-known/openid-configuration"
    try:
        with urllib.request.urlopen(discovery_url, timeout=5) as resp:  # nosec B310 - fixed https issuer
            doc = json.loads(resp.read().decode("utf-8"))
        jwks_uri = doc.get("jwks_uri")
        if jwks_uri:
            return jwks_uri
    except Exception as exc:  # noqa: BLE001
        print(f"OIDC discovery failed ({discovery_url}): {exc}; falling back to conventional path")

    return f"{OIDC_ISSUER}/.well-known/jwks.json"


# Cache the JWKS client at module scope so signing keys are reused across warm invocations.
_jwk_client = PyJWKClient(_resolve_jwks_uri())


def handler(event, _context):
    token = _extract_token(event)

    # Fail closed: a TOKEN authorizer event must carry methodArn. If it is absent
    # the request is malformed, so deny against the narrowest possible resource
    # rather than defaulting to "*" (which would scope an Allow to every method).
    method_arn = event.get("methodArn")
    if not method_arn:
        print("Authorizer event missing methodArn; denying")
        return _policy("unauthorized", "Deny", DENY_RESOURCE)

    try:
        signing_key = _jwk_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=OIDC_AUDIENCE,
            issuer=OIDC_ISSUER,
            options={"require": ["exp", "iss", "aud"]},
        )
    except Exception as exc:  # noqa: BLE001
        print(f"JWT validation failed: {exc}")
        return _policy("unauthorized", "Deny", method_arn)

    if not _has_required_group(claims):
        print(f"Caller {claims.get('sub', '?')} is missing required group '{REQUIRED_GROUP}'")
        return _policy(claims.get("sub", "user"), "Deny", method_arn)

    return _policy(
        claims.get("sub", "user"),
        "Allow",
        method_arn,
        context={
            "sub": str(claims.get("sub", "")),
            "upn": str(claims.get("upn", claims.get("email", ""))),
        },
    )


def _has_required_group(claims: dict) -> bool:
    for claim in _GROUP_CLAIMS:
        value = claims.get(claim)
        if isinstance(value, str):
            value = [value]
        if value and REQUIRED_GROUP in value:
            return True
    return False


def _extract_token(event) -> str:
    # TOKEN authorizers deliver the raw header in `authorizationToken`; REQUEST
    # authorizers put it under headers.Authorization. Support both.
    header = event.get("authorizationToken") or event.get("headers", {}).get("Authorization", "")
    return header[7:] if header.lower().startswith("bearer ") else header


def _policy(principal, effect, resource, context=None):
    doc = {
        "principalId": principal,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": resource}
            ],
        },
    }
    if context:
        doc["context"] = context
    return doc
