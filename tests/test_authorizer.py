"""Tests for the OIDC TOKEN authorizer's fail-closed behavior.

A code review flagged that a missing `methodArn` must not default to a wildcard
resource. These tests pin that the authorizer denies against a narrow,
partition-neutral sentinel when `methodArn` is absent, and that the policy
builder shapes the IAM document correctly.
"""
import authorizer


class TestFailClosed:
    def test_missing_method_arn_denies(self):
        policy = authorizer.handler({"authorizationToken": "Bearer x"}, None)
        stmt = policy["policyDocument"]["Statement"][0]
        assert stmt["Effect"] == "Deny"

    def test_missing_method_arn_uses_narrow_sentinel_not_wildcard(self):
        policy = authorizer.handler({"authorizationToken": "Bearer x"}, None)
        resource = policy["policyDocument"]["Statement"][0]["Resource"]
        assert resource == authorizer.DENY_RESOURCE
        # The sentinel must not be a bare wildcard, and must end at the deny path.
        assert resource != "*"
        assert resource.endswith("/deny")

    def test_deny_sentinel_is_partition_neutral(self):
        # arn:*: so the sentinel is correct in commercial and GovCloud alike.
        assert authorizer.DENY_RESOURCE.startswith("arn:*:execute-api:")


class TestPolicyBuilder:
    def test_allow_policy_shape(self):
        policy = authorizer._policy("alice", "Allow", "arn:aws:execute-api:region:acct:api/stage/GET/x")
        assert policy["principalId"] == "alice"
        stmt = policy["policyDocument"]["Statement"][0]
        assert stmt["Effect"] == "Allow"
        assert stmt["Action"] == "execute-api:Invoke"

    def test_context_is_included_when_provided(self):
        policy = authorizer._policy("alice", "Allow", "arn:x", context={"sub": "alice"})
        assert policy["context"] == {"sub": "alice"}

    def test_context_absent_when_not_provided(self):
        policy = authorizer._policy("alice", "Deny", "arn:x")
        assert "context" not in policy
