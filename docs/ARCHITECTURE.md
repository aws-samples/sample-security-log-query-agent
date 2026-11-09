# Architecture

## Overview

The Security Log Query Agent is a serverless natural-language-to-SQL system over
a centralized security log archive. It is model-agnostic (Amazon Bedrock
Converse API with tool use), cross-account (query account reads a Log Archive
account), and read-only by construction. This document is the deep dive; see
[`DEPLOYMENT.md`](DEPLOYMENT.md) for the runbook.

---

## Request flow

1. **User** authenticates against an OIDC identity provider and obtains a JWT
   containing a group claim.
2. The request reaches the ingress (commercial mainline: a private API Gateway
   reached through an `execute-api` interface VPC endpoint, whose ID the API's
   resource policy requires; GovCloud/IL5 variant: a CNAP ingress path — see
   below). The caller runs inside that VPC.
3. The **edge authorizer** validates the JWT signature against the IdP JWKS,
   checks issuer/audience/expiry, and **requires the designated security group
   claim**. The result is cached per token.
4. The **API Handler Lambda** (`securitylogagent-exec-role`) runs the agent loop:
   - Calls **Bedrock Converse** with the analyst question and a single
     `run_athena_query` tool declared in `toolConfig`.
   - When Converse returns a `toolUse` block, the Lambda executes the generated
     **read-only** SQL against Athena and returns the rows as a `toolResult`
     content block.
   - Loops (bounded max turns and a response deadline) until the model returns a
     normal message, then returns the plain-English answer, the SQL that was run,
     and the Athena query execution IDs.
5. **Athena** runs the query in a locked-down workgroup (`securitylogagent-wg`)
   against the **cross-account Glue Data Catalog** registered as an Athena
   `DataCatalog`, reading the central log objects in the **Log Archive account**
   S3 bucket.

---

## The model-agnostic Converse tool-use loop

The agent uses the Bedrock **Converse API** rather than a managed Bedrock Agent
or a model-specific `InvokeModel` body. This is what makes the model a single
deploy-time parameter:

- One tool, `run_athena_query`, is declared via `toolConfig` with an input schema
  (`{ "sql": "<SQL string>" }`).
- The loop is: send messages -> if the reply contains a `toolUse` block, run the
  SQL and append a `toolResult` -> resend -> repeat until a reply with no tool use.
- Because Converse normalizes the request/response shape across model families,
  **changing only the `modelId` context parameter** switches vendors with no
  code change. This was validated by driving the identical code against both an
  Amazon Nova model and an Anthropic Claude model.

### The inference-profile finding (important)

Current Anthropic Claude models on Bedrock are **not** invocable by bare model ID
on-demand. A Converse call with a bare Claude model ID (e.g.
`anthropic.claude-sonnet-4-5-20250929-v1:0`) fails with:

```
ValidationException: ... on-demand throughput isn't supported ... retry with an inference profile
```

**Fix:** pass the cross-Region **inference profile** ID instead
(`us.anthropic.claude-sonnet-5`). The Converse `modelId` field
accepts a bare model ID **or** an inference-profile ID/ARN transparently, so this
is purely a value change to the `modelId` parameter — no code change.

**Amazon Nova** models (e.g. `amazon.nova-pro-v1:0`) work by **bare model ID**;
they do not require an inference profile.

Discover the available profiles with `aws bedrock list-inference-profiles`.

---

## IAM isolation

`securitylogagent-exec-role` is intentionally minimal and disjoint from any other
role:

- `athena:StartQueryExecution` / `StopQueryExecution` / `GetQueryExecution` /
  `GetQueryResults` / `GetWorkGroup` / `GetDataCatalog`, scoped to the
  `securitylogagent-wg` workgroup and the cross-account data catalog.
- Cross-account `glue:Get*` on the Log Archive catalog / database / tables.
- Cross-account `s3:GetObject` / `s3:ListBucket` on the central log bucket only
  (`centralBucketName`).
- Cross-account `kms:Decrypt` / `DescribeKey` on the central log key
  (`centralLogKmsKeyArn`; without it, any key in the Log Archive account), only
  when called through Amazon S3 (`kms:ViaService`).
- `bedrock:InvokeModel` (which also authorizes Converse) on inference profiles in
  the query account and on foundation models.
- **No write actions on the log data.** The only read/write grant is on the
  private Athena results bucket. No Knowledge Base access.

---

## Data controls (no Lake Formation)

Cross-account read is granted with three native mechanisms — deliberately **not**
Lake Formation, which keeps the pattern portable across partitions (including
partitions where Lake Formation is unavailable):

1. **S3 bucket policy** statement on the LZA central log bucket granting the
   query-account role read.
2. **Glue catalog resource policy** in the Log Archive account granting the
   query-account role `Get*` on the `security_central_logs` database and tables.
3. **KMS key policy** grant on the central log CMK for `Decrypt` / `DescribeKey`.

The S3 + KMS statements are **owned by the LZA config** (the bucket and key are
LZA-managed), so the `LogArchiveGrants` stack does **not** attach them directly.
It emits them as stack outputs (`AddToCentralLogBucketPolicy`,
`AddToCentralLogKmsKeyPolicy`) to paste into the LZA config; attaching them out of
band would be reverted by the LZA pipeline as drift. See
[`DEPLOYMENT.md`](DEPLOYMENT.md) step 3.

---

## Read-only-by-construction guarantee

The query path cannot mutate data, enforced at three independent points:

1. **Handler SQL guard** — the handler parses the model-generated SQL with
   `sqlglot` (Presto dialect, which Athena uses) and accepts it only if it is
   exactly one statement and that statement is a `SELECT` (including a `WITH`
   that wraps one). Multi-statement input and every other statement type are
   rejected; a forbidden word inside an identifier or string literal is not.
2. **Read-only IAM role** — `securitylogagent-exec-role` has no write actions on
   S3, Glue, KMS, or Athena results beyond its own scratch results bucket.
3. **Locked-down Athena workgroup** — `securitylogagent-wg` enforces its output
   configuration, disables client-side override, and cancels any query that
   would scan more than `bytesScannedCutoffPerQuery`.

Even if the model were prompted adversarially to emit a mutating statement, all
three layers must be defeated for any write to occur; the IAM role alone makes it
impossible.

---

## Response deadline

API Gateway ends a REST API integration after 29 seconds, so the API handler is
set to the same timeout and works to a 22-second deadline
(`RESPONSE_DEADLINE_SECONDS`). Past it, the handler starts no new model turn,
and an Athena query still running is cancelled with `StopQueryExecution` rather
than left to scan and bill. The response then says the request stopped and
suggests narrowing it. A model call that starts just before the deadline can
still run past 29 seconds; questions that need longer belong in an asynchronous
design (see "Production hardening" in [`DEPLOYMENT.md`](DEPLOYMENT.md)).

## Audit logging and untrusted results

The API handler writes one JSON audit record per step to its CloudWatch log
group (retained for one year, and kept when the stack is deleted):

| Record | Fields |
|---|---|
| `request_received` | request ID, session ID, caller (`sub` and `upn` from the authorizer), question |
| `sql_accepted` / `sql_rejected` | the SQL the model proposed and the guard's decision |
| `query_finished` / `query_stopped` / `query_error` | Athena query execution ID, final state or reason |
| `request_finished` | outcome, HTTP status, query execution IDs, elapsed time |

Query results are log data, and fields such as user agents, error messages,
URLs, and finding descriptions can carry attacker-controlled text. Each result
cell is capped at 500 characters before it reaches the model, and the system
prompt tells the model to treat tool results only as data. Unexpected errors are
logged and the caller receives a generic message with the request ID.

## The four Glue tables

The grant stack defines four external tables in the `security_central_logs`
database over the LZA central log bucket:

| Table | Source prefix (under the central log bucket) | SerDe / format |
|---|---|---|
| `cloudtrail` | `cloudtrail-organization/AWSLogs/<ORG_ID>/` | CloudTrail JSON SerDe |
| `vpc_flow_logs` | `vpc-flow-logs/AWSLogs/` | space-delimited `LazySimpleSerDe` |
| `guardduty` | `guardduty/` | JSON SerDe over finding records |
| `network_firewall` | `firewall/` | JSON SerDe over flow/alert records |

The tables are non-partitioned for demo simplicity (full scans over small data).
**For production**, add partition projection or a Glue crawler with partition
columns (account, region, date) to bound Athena scan cost and latency.

---

## Stacks

| Stack | Account | Contents |
|---|---|---|
| `SecurityLogQuery-App` | Query | Private API Gateway (pinned to one `execute-api` VPC endpoint, which the deployer supplies) + edge authorizer, `securitylogagent-exec-role`, API handler Lambda (Converse agent loop) and its audit log group, Athena workgroup `securitylogagent-wg` + cross-account `DataCatalog`, Athena results bucket (7-day expiry) |
| `SecurityLogQuery-LogArchiveGrants` | Log Archive | Glue database `security_central_logs`, the four external tables, Glue catalog resource policy; emits the S3/KMS statements for the LZA config |

---

## GovCloud / IL5 variant

The commercial mainline above is the default. For a DoD-style AWS GovCloud (US)
IL5 deployment, the following deltas apply:

- **CNAP ingress.** Instead of a directly fronted private API Gateway, ingress is
  a Cloud Native Access Point: a public, corp-locked **ALB + WAF** in a Network
  account, forced through a **Transit Gateway** to an **Inspection VPC / Network
  Firewall** (symmetric inspection via appliance mode + TGW route tables), then to
  an **internal ALB + WAF** (AWS managed Common + SQLi rule sets) in the app VPC,
  and finally to the private API Gateway. The agent VPC is isolated (disjoint
  routes and IAM from any other app).
- **Cognito `auth-fips` hosted UI.** In GovCloud the Cognito hosted-UI domain
  resolves at `https://<prefix>.auth-fips.<region>.amazoncognito.com` (note
  `auth-fips`, not `auth`); the commercial `auth` host does not resolve. Use the
  `auth-fips` host for the OAuth `/authorize` and `/token` URLs. Because
  `authenticate-cognito` on an ALB requires the user pool in the same account as
  the ALB, a cross-account CNAP ingress uses an SPA auth-code + PKCE flow and
  decodes the group claim from the Bearer ID token at the app.
- **Model path (standard GovCloud).** The GovCloud variant uses the same
  Amazon Bedrock Converse path as the commercial mainline, against the FIPS
  endpoint (`bedrock-runtime-fips.<region>.api.aws`) with an entitled model or a
  GovCloud cross-region inference profile (CRIS). Because the model is a
  deploy-time parameter, no code changes — only the model/profile ID and the
  FIPS endpoint. This is the recommended path for a healthy GovCloud account.
  - *Fallback for an agreement-held account (edge case, not the default).* If an
    account's Anthropic Claude Marketplace agreement is fraud-held and cannot be
    re-established, the loop can be pointed at an alternative entitled model, or
    at an OpenAI-compatible Chat Completions endpoint with function calling, via
    the same deploy-time parameter. This is a workaround for an account-state
    problem, not an architectural requirement of GovCloud, and it is out of
    scope for the reference pattern.
- **SSE_S3 vs SSE_KMS.** The Athena workgroup uses `SSE_S3` in the variant;
  `SSE_KMS` requires an explicit CMK ARN in GovCloud.
- **Private CDK bootstrap qualifier.** The LZA-managed CDKToolkit uses a private
  bootstrap qualifier (set in `cdk.json`) rather than the default `hnb659fds`.
