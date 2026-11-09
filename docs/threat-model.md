# Threat Model: Security Log Query Agent

AWS Prescriptive Guidance reference sample. Structured for the Threat Composer model
(assumptions / threats / mitigations) and the four threat-modeling questions:
what are we working on, what can go wrong, what are we doing about it, did we do a good
enough job. The machine-readable companion is [`threat-model.tc.json`](threat-model.tc.json),
importable into [Threat Composer](https://github.com/awslabs/threat-composer).

## What are we working on

A serverless, read-only, natural-language-to-SQL assistant over a centralized security
log archive. An analyst asks a plain-English question; a foundation model (Amazon Bedrock
Converse API with tool use) proposes ONE read-only Athena SQL query; a dedicated read-only
IAM role runs it against the LZA central security-log Glue catalog in a dedicated Log
Archive account, and the model summarizes the returned rows plus the exact SQL it ran.

The model holds no credentials and takes no action; it only proposes SQL. Authorization is
enforced deterministically in code and IAM, not by the model. Read-only is guaranteed at
three independent layers.

Scope: the commercial mainline variant (private API Gateway -> OIDC TOKEN Lambda authorizer
-> API handler Lambda -> Athena locked-down workgroup -> cross-account Glue + central-log
S3/KMS in the Log Archive account). The GovCloud/IL5 ingress variant (CNAP: ALB + WAF ->
Transit Gateway -> Network Firewall -> internal ALB) adds ingress threats documented
separately in `ARCHITECTURE.md`.

## Assumptions

1. The LZA landing zone already delivers CloudTrail, VPC Flow Logs,
   GuardDuty, and Network Firewall logs to the central S3 bucket in a dedicated Log Archive
   account. This sample does not create or own that log data.
2. The deployer supplies an `execute-api` interface VPC endpoint, and analysts' clients
   run inside that VPC. The stack does not create the endpoint.
3. The OIDC IdP (Entra ID, Cognito, Okta) is trusted, issues correctly scoped group claims,
   and publishes a valid JWKS over HTTPS.
4. The central log bucket and its KMS CMK are LZA-managed; cross-account grants are applied
   through LZA config and the LZA pipeline, not out of band.
5. The deployer supplies a Bedrock model/inference-profile ID that is entitled and on the
   AWS-approved list for their partition and compliance regime.
6. This is a reference sample (MIT-0), explicitly not production-hardened; a production
   deployment tightens IAM, network, encryption, and data controls against its own
   requirements before using real data.

## What can go wrong, and what we do about it

| # | STRIDE | Priority | Threat | Mitigations | Residual |
|---|--------|----------|--------|-------------|----------|
| T1 | Tampering | Medium | Analyst or prompt-injection coerces the model into proposing a mutating/destructive SQL statement, or attacker-controlled text in returned log rows steers the model's summary | Handler SQL guard (AST parse via sqlglot: exactly one statement, SELECT/WITH only, rejects multi-statement and non-SELECT forms); read-only IAM role with no write actions; locked-down Athena workgroup; result cells capped at 500 characters and a system-prompt rule to treat tool results as data only; every proposed statement, guard decision, and Athena query ID written to the audit log | Low for writes: three independent layers; the IAM role alone makes mutation impossible. Medium for a misleading summary: the prompt rule is advisory, so the response returns the exact SQL and query IDs for the analyst to verify. Production adds an Amazon Bedrock guardrail |
| T2 | Spoofing / Elevation | Medium | Unauthorized actor without a valid group-claim token reaches the query API | PRIVATE API Gateway whose resource policy denies any request not arriving through the required `execute-api` VPC endpoint (evaluated before the authorizer); OIDC authorizer (signature, issuer, audience, expiry + required group claim); caller identity recorded in the audit log | Low: 5-min authorizer cache means a revoked token stays valid up to TTL; acceptable and documented. `aws:PrincipalOrgID` is not used on the API because bearer-token callers carry no AWS principal |
| T3 | Information Disclosure | Low | Agent role over-scoped, reaches data beyond the central logs | All statements ARN-scoped (workgroup, catalog/db/tables, one bucket, model ARNs); `kms:Decrypt` scoped to the central-log key when `centralLogKmsKeyArn` is set, and always limited to calls through Amazon S3 (`kms:ViaService`); remaining wildcards object-level or read-only, documented in nag-suppressions | Low: role cannot reach any other bucket or catalog. Without `centralLogKmsKeyArn`, the role's KMS grant covers any Log Archive key used through S3; the key policies decide which keys actually allow it. The key-policy statement is constrained by `aws:PrincipalOrgID` |
| T4 | Information Disclosure | Low | Authorized analyst issues broad queries over sensitive logs | Group-claim gate (analyst is already entitled); MaxResults=100 + system-prompt LIMIT and time filters | Accepted: read access to data the group is entitled to; control is membership, not query shape |
| T5 | Spoofing | Medium | JWKS discovery / token validation weakness | HTTPS-fixed issuer, RS256 pinned (no alg:none), issuer/audience/expiry required, keys cached | Depends on IdP trust (assumption 2); deployer sets issuer/audience/group correctly, documented |
| T6 | Information Disclosure | Low | Query-results bucket exposes staged output | Block Public Access ALL, enforceSSL, versioning, SSE-S3, server access logging; results expire after 7 days and noncurrent versions after 1 day | Low: copies of log data kept briefly, reproducible; private bucket. SSE-S3 vs CMK is a documented sample simplification |
| T7 | Tampering / compliance | Low | Deployer selects an unentitled/unapproved/untrusted model | First-party Bedrock Converse (no 3rd-party GenAI, no bundled dataset); invoke scoped to inference-profile/foundation-model ARNs; GovCloud FIPS endpoint | Out of scope for the sample: model choice/entitlement is the deployer's responsibility (assumption 4) |
| T8 | Denial of Service | Low | Repeated/expensive questions drive unbounded loops or large scans | MAX_TOOL_TURNS=6; 22-second response deadline after which no new model turn starts and a running Athena query is cancelled (`StopQueryExecution`); 29-second Lambda timeout matching the API Gateway limit; Athena workgroup `bytesScannedCutoffPerQuery` (default 10 GiB); Converse maxTokens=1024; group-gated surface | Low: `MaxResults=100` caps rows returned, and the scan cutoff caps bytes scanned per query. Non-partitioned demo tables mean a broad question reaches the cutoff quickly. Production mitigations: partition projection, reserved concurrency, and API stage throttling, flagged as deployment steps |

## Did we do a good enough job

Every threat is tied to one or more implemented mitigations present in the committed code
(`lambda/api-handler/api_handler.py`, `lambda/authorizer/authorizer.py`,
`lib/logquery-stack.ts`) and to the documented, justified cdk-nag suppressions
(`lib/nag-suppressions.ts`). The two items marked accepted/out-of-scope (T4 analyst
entitlement, T7 model choice) are deliberate boundaries of a reference sample, not gaps.
cdk-nag (AwsSolutions + NIST 800-53 R5) runs clean with suppressions documented per
rule, and Bandit reports no issues; see `../security-scans/`. npm audit reports three
moderate findings, all one `minimatch` advisory (GHSA-g3hv-75wg-m249) in the copy bundled
inside `aws-cdk-lib`. It is a build-time dependency of `cdk synth` and is not deployed;
the current `aws-cdk-lib` release still bundles it, so update `aws-cdk-lib` when a fixed
release ships. The security-critical controls
(the read-only SQL guard and audit records behind T1, the authorizer fail-closed path
behind T2, and the response deadline behind T8) are pinned by unit tests in `../tests/`,
and the infrastructure controls (VPC endpoint pin, scoped bucket and key grants, scan
cutoff, timeout, packaged dependencies) by the infrastructure tests in `../test/`.

This is a live document: update it as the sample evolves, and re-review the GovCloud/IL5
ingress deltas (CNAP, WAF, Network Firewall) if that variant is built out.
