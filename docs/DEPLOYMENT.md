# Deployment Runbook

This runbook deploys the Security Log Query Agent onto an AWS Landing Zone
Accelerator (LZA) landing zone. The **commercial mainline**
is the default; a **GovCloud / IL5 variant** is noted where it differs (see also
the "GovCloud / IL5 variant" section of [`ARCHITECTURE.md`](ARCHITECTURE.md)).

> **Other landing zones.** The Glue tables read the LZA central-log bucket layout
> (prefixes below). AWS Control Tower's log bucket holds CloudTrail (and, before
> landing zone 4.0, AWS Config) only, so VPC Flow Logs, GuardDuty, and Network
> Firewall are not there by default. To use another layout, set
> `centralBucketName` and adjust the table locations in
> `lib/logarchive-grant-stack.ts`.

The deployment has two halves in two accounts:

- **`SecurityLogQuery-LogArchiveGrants`** — deployed into the **Log Archive
  account**; creates the Glue database, the four external tables, and the Glue
  catalog resource policy, and emits the S3 + KMS statements to wire into the LZA
  config.
- **`SecurityLogQuery-App`** — deployed into the **query account**; the Lambda
  agent loop, ingress, Athena workgroup, and cross-account Data Catalog.

---

## 0. Prerequisites

| Requirement | Notes |
|---|---|
| Node 20+, AWS CDK v2 | the repo pins the CDK CLI; use `npx cdk` |
| Python 3.12 with `pip` | `cdk synth` installs each function's `requirements.txt` into its package with local `pip`. If `pip` is unavailable it uses Docker (or Finch) with the Lambda Python build image instead |
| Query + Log Archive account access | short-lived creds; query account for the app, Log Archive for grants |
| LZA centralized logging | delivering the four sources to the central log bucket (below) |
| A VPC with an `execute-api` interface endpoint | the API is private. Callers, including your test client, must run inside this VPC (or a network routed to it) and reach the API through this endpoint. Pass its ID as `apiResourcePolicySourceVpce` (below) |
| An OIDC identity provider | issuer URL, audience (client ID) for the API, and the group value analysts must carry in a `groups`, `roles`, or `cognito:groups` claim |
| Bedrock model access | for your chosen model — **note the inference-profile requirement for current Claude models** (below) |
| CDK bootstrap | both accounts bootstrapped for CDK v2 (see the IL5 variant note on the private bootstrap qualifier) |

### The `execute-api` VPC endpoint

The stack does not create the endpoint, because landing zones usually provision
interface endpoints centrally and a second endpoint for the same service in a VPC
conflicts on its private DNS name. Check for an existing one first:

```bash
aws ec2 describe-vpc-endpoints --region <region> \
  --filters Name=service-name,Values=com.amazonaws.<region>.execute-api \
  --query 'VpcEndpoints[].{id:VpcEndpointId,vpc:VpcId,privateDns:PrivateDnsEnabled}'
```

If there is none in the VPC your analysts' clients use, create one:

```bash
aws ec2 create-vpc-endpoint --region <region> \
  --vpc-id <VPC_ID> --vpc-endpoint-type Interface \
  --service-name com.amazonaws.<region>.execute-api \
  --subnet-ids <SUBNET_ID_1> <SUBNET_ID_2> \
  --security-group-ids <SG_ALLOWING_443_FROM_CLIENTS> \
  --private-dns-enabled
```

The API's resource policy denies every request that does not arrive through this
endpoint.

### Centralized log delivery (all four sources)

The pattern queries logs already delivered by the LZA to the central log bucket
in the Log Archive account (by default
`aws-accelerator-central-logs-<LOG_ARCHIVE_ACCOUNT>-<region>`; set
`centralBucketName` if yours differs). Confirm all four
sources are present before deploying:

| Source | Typical S3 prefix |
|---|---|
| CloudTrail (organization) | `cloudtrail-organization/AWSLogs/<ORG_ID>/` |
| VPC Flow Logs | `vpc-flow-logs/AWSLogs/` |
| GuardDuty | `guardduty/` |
| Network Firewall | `firewall/` |

If a source is not being delivered, enable it in the LZA `security-config.yaml`
/ `network-config.yaml` and run the pipeline first — this pattern does not create
the log delivery, it reads it.

### Bedrock model access and the inference-profile requirement

Grant model access for the model you intend to use. **Current Anthropic Claude
models are not invocable by bare model ID on-demand** — an on-demand
`InvokeModel`/`Converse` with a bare Claude model ID returns:

```
ValidationException: ... on-demand throughput isn't supported ... retry with an inference profile
```

Use the cross-Region **inference profile** ID instead (e.g.
`us.anthropic.claude-sonnet-5`). Amazon Nova models work by bare
model ID. List the inference profiles available in your account/region:

```bash
aws bedrock list-inference-profiles --region <region>
```

Models move from `ACTIVE` to `LEGACY` and then reach end of life, so check that
the model behind your profile is still `ACTIVE` before you deploy:

```bash
aws bedrock list-foundation-models --region <region> --by-provider anthropic \
  --query "modelSummaries[].[modelId,modelLifecycle.status]" --output table
```

Pass whichever value you choose to the app stack as `-c modelId=...` — the
Converse `modelId` accepts a bare model ID **or** an inference-profile ID/ARN
transparently.

---

## 1. Build

```bash
npm ci
npm run build      # tsc
```

You do not bundle the Lambda dependencies by hand. During `cdk synth` (and so
during `cdk deploy`), each function's `requirements.txt` is installed into its
deployment package for the Lambda runtime (Python 3.12, x86_64):

- `lambda/api-handler` -- sqlglot (SQL statement parsing/validation). `boto3`
  is provided by the Lambda runtime.
- `lambda/authorizer` -- PyJWT + cryptography (JWT validation).

The local path runs `python3 -m pip install --platform manylinux2014_x86_64
--only-binary=:all: --python-version 3.12` into the package, so it produces
Linux wheels on macOS and Windows as well. If that fails, CDK runs the same
install in the Lambda Python build image with Docker.

### Set the context once

Both stacks are synthesized on every `cdk` command, so every required value is
needed whichever stack you deploy. Set them once in your shell:

```bash
CTX=(
  -c queryAccount=<QUERY_ACCOUNT>
  -c logArchiveAccount=<LOG_ARCHIVE_ACCOUNT>
  -c region=<region>
  -c orgId=<ORG_ID>
  -c oidcIssuer=<OIDC_ISSUER_URL>
  -c oidcAudience=<OIDC_AUDIENCE>
  -c requiredGroup=<GROUP_VALUE>
  -c apiResourcePolicySourceVpce=<VPCE_ID>
  -c modelId=us.anthropic.claude-sonnet-5
  # Recommended: scope kms:Decrypt to the central-log key.
  -c centralLogKmsKeyArn=<CENTRAL_LOG_KMS_KEY_ARN>
)
```

Optional values, with their defaults:

| Context key | Default | Purpose |
|---|---|---|
| `centralBucketName` | `aws-accelerator-central-logs-<LOG_ARCHIVE_ACCOUNT>-<region>` | central log bucket, used by both stacks |
| `centralLogKmsKeyArn` | unset | without it, `kms:Decrypt` covers any key in the Log Archive account, limited to calls made through Amazon S3 |
| `bytesScannedCutoffPerQuery` | `10737418240` (10 GiB) | Athena cancels any query that would scan more (minimum 10 MB) |
| `glueDatabase` | `security_central_logs` | Glue database for the four tables |
| `glueCatalogName` | `security_central_logs_catalog` | Athena data catalog name in the query account |
| `workgroupName` | `securitylogagent-wg` | Athena workgroup |
| `roleName` | `securitylogagent-exec-role` | agent execution role |
| `modelId` | `us.anthropic.claude-sonnet-5` | Bedrock model or inference profile |
| `modelTemperature` | unset | sampling temperature from 0 to 1; when unset, no `temperature` is sent, because some current models reject it |

Check the configuration before deploying anything:

```bash
npx cdk synth "${CTX[@]}" --quiet
```

This also runs cdk-nag (AwsSolutions and NIST 800-53 R5); synthesis fails on any
unsuppressed finding.

### Run the tests

```bash
npm test                     # infrastructure tests (compiles first)

python3 -m venv .venv && . .venv/bin/activate
pip install -r tests/requirements.txt
pytest tests/ -q             # Lambda unit tests; no AWS calls
```

The infrastructure tests check that the function packages contain their
dependencies, the API accepts only the supplied VPC endpoint, both stacks use the
configured bucket, the function fits the API Gateway timeout, and the app
synthesizes cleanly. The packaging test runs `pip`, so it needs access to PyPI.

---

## 2. Deploy the Log Archive grants

Run with **Log Archive account** credentials:

```bash
npx cdk deploy SecurityLogQuery-LogArchiveGrants "${CTX[@]}"
```

This creates the Glue database `security_central_logs`, the `cloudtrail`,
`vpc_flow_logs`, `guardduty`, and `network_firewall` external tables, and the
Glue catalog resource policy granting the query-account role `Get*`. It prints
two outputs needed in the next step:

- `AddToCentralLogBucketPolicy`
- `AddToCentralLogKmsKeyPolicy`

---

## 3. Wire the S3 + KMS grants through the LZA (NOT out of band)

The central log bucket and its CMK are **LZA-managed**. Paste the two emitted
statements into the LZA config so they survive the pipeline:

- Add `AddToCentralLogBucketPolicy` to the central log bucket policy in the LZA
  config (`bucket-policies/central-log-bucket.json` or equivalent).
- Add `AddToCentralLogKmsKeyPolicy` to the central log KMS key policy.

Then run the LZA pipeline so the grants apply.

> **Do not** attach these with a manual `aws s3api put-bucket-policy` /
> `put-key-policy`. The LZA reconciles managed resources back to the config
> source in S3 and will revert an out-of-band change as drift, silently breaking
> cross-account reads on the next pipeline run.

---

## 4. Deploy the app into the query account

Run with **query account** credentials:

```bash
npx cdk deploy SecurityLogQuery-App "${CTX[@]}"
```

Stack outputs:

| Output | Use |
|---|---|
| `ApiUrl` | query endpoint base URL (`.../prod/`); POST to `query` under it |
| `ApiHandlerFunctionName` | function to invoke for the backend smoke test |
| `ApiHandlerLogGroupName` | audit log: caller, question, SQL, Athena query IDs, outcome |
| `AthenaResultsBucketName` | Athena query results (expire after 7 days) |
| `WorkgroupName`, `LogAgentRoleArn`, `ApiId` | workgroup, agent role, API ID |

---

## 5. Smoke test

### Backend (direct Lambda invoke)

This bypasses the edge authorizer and the network path, so it isolates the agent
loop. Run with query account credentials:

```bash
FN=$(aws cloudformation describe-stacks --stack-name SecurityLogQuery-App --region <region> \
  --query "Stacks[0].Outputs[?OutputKey=='ApiHandlerFunctionName'].OutputValue" --output text)

aws lambda invoke --function-name "$FN" --region <region> \
  --cli-binary-format raw-in-base64-out \
  --payload '{"body": "{\"question\": \"How many CloudTrail events were logged in the last day?\"}"}' \
  response.json && cat response.json
```

Expected: `"statusCode": 200`, and a `body` holding `answer`, the `sql` the model
ran, and `queryExecutionIds` (open any of them in the Athena console's query
history). Try each source, for example "Which source IPs had the most REJECTED
VPC flows yesterday?", "List active GuardDuty findings by severity", and "Show
blocked flows from Network Firewall in the last hour".

### End to end (through the private API)

Run this **from a host inside the VPC that holds the `execute-api` endpoint**,
for example an EC2 instance reached through Session Manager. From anywhere else
the request is refused.

1. Obtain an OIDC token (JWT) from your identity provider for the configured
   audience, as a user who holds the required group. The authorizer accepts the
   group in the `groups`, `roles`, or `cognito:groups` claim. With Microsoft Entra
   ID, enable group claims on the app registration (or use an app role, which
   appears in `roles`); with Amazon Cognito, add the user to a user-pool group.
2. Call the API:

```bash
API_URL=$(aws cloudformation describe-stacks --stack-name SecurityLogQuery-App --region <region> \
  --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text)

curl -sS -X POST "${API_URL}query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question": "Show failed console logins in the last 24 hours"}'
```

With private DNS enabled on the endpoint, the `ApiUrl` host resolves to the
endpoint inside the VPC. A `401` means the `Authorization` header was missing; a
`403` means the token was refused (issuer, audience, expiry, or group) or the
request did not come through the endpoint.

### Response time limit

API Gateway ends a REST API integration after **29 seconds** and returns `504`.
The function is set to the same 29 seconds. After 22 seconds the handler stops
starting new model turns and cancels any Athena query still running
(`StopQueryExecution`), so most requests return an answer or a clear "stopped"
message rather than a `504`. A model call that starts just before the deadline
can still run past 29 seconds. Questions that need longer, such as wide time
ranges over non-partitioned tables, need an asynchronous design (submit, then
poll for the result); see "Production hardening" below.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ValidationException: on-demand throughput isn't supported` | You passed a bare Claude model ID. Use a `us.` inference-profile ID (`aws bedrock list-inference-profiles`). |
| `Query FAILED` from Athena | Glue tables not populated / wrong prefix, or the cross-account grant did not apply. Confirm the grant stack ran and the LZA pipeline applied the S3/KMS statements. |
| Cross-account read denied | The S3/KMS statements were attached out of band and reverted by the LZA. Wire them through the LZA config (step 3) and re-run the pipeline. |
| Authorizer always Deny | JWKS / issuer / audience mismatch, or the token lacks the required security group claim. |
| Access denied on Bedrock | Model access not granted in this account/region, or the region-deny SCP blocks Bedrock. Grant model access and confirm the model/profile is reachable from the query account's region. |
| `Missing required CDK context value` | Every required value is needed for either stack. Pass the full `"${CTX[@]}"` set (step 1). |
| Synth fails while bundling | Local `pip` could not build the package and Docker is unavailable. Install Python 3.12 with `pip`, or start Docker or Finch, and re-run. |
| `504` from the API | The request ran past API Gateway's 29-second limit. Narrow the question or the time range (see "Response time limit"). |
| Answer says the query was stopped | The Athena query reached the response deadline or the workgroup's `bytesScannedCutoffPerQuery`. Narrow the time range, or add partitions to the tables. |
| `403` through the API | Token refused by the authorizer, or the request did not come through the `apiResourcePolicySourceVpce` endpoint. |

---

## Production hardening

The sample is a reference implementation. Before using it with real data,
address these, which the code leaves to the deploying team:

| Area | Current sample | Production step |
|---|---|---|
| Response time | synchronous, 29-second ceiling | asynchronous API (submit a question, poll for the answer), with a queue and a dead-letter queue |
| Scan cost | non-partitioned tables, 10 GiB per-query cutoff | partition projection or an AWS Glue crawler with partition columns; set `bytesScannedCutoffPerQuery` to your budget |
| Prompt injection | system-prompt rule, capped result cells, read-only SQL guard and IAM | an Amazon Bedrock guardrail on the Converse call (`guardrailConfig`), tuned for your data |
| Concurrency | no reserved concurrency | set reserved concurrency on both functions and API Gateway stage throttling |
| Failure handling | synchronous calls, no DLQ | a DLQ once the API is asynchronous |
| Encryption | SSE-S3 results bucket, service-managed log encryption | customer managed KMS keys on the results bucket and both log groups |
| Key scope | `kms:Decrypt` on any Log Archive key through S3, unless `centralLogKmsKeyArn` is set | always set `centralLogKmsKeyArn` |
| API logging | execution and access logging off | enable API Gateway access and execution logs |

Costs to expect beyond the Lambda, API Gateway, and Amazon Bedrock calls: Athena
charges per byte scanned, and the results bucket stores each query's output for
seven days (older object versions for one more day). The audit log group keeps
records for one year.

---

## Teardown

```bash
# Query account
npx cdk destroy SecurityLogQuery-App "${CTX[@]}"

# Log Archive account
npx cdk destroy SecurityLogQuery-LogArchiveGrants "${CTX[@]}"
```

Then remove the two statements you added to the LZA central-log bucket / KMS
policies and run the pipeline once more to reconcile. The two Lambda log groups
are retained on stack deletion because the api-handler group is the audit trail;
delete them in CloudWatch Logs when you no longer need the records.

---

## GovCloud / IL5 variant deltas

- **Ingress:** CNAP (public ALB + WAF -> Transit Gateway -> Network Firewall
  inspection -> internal ALB -> private API Gateway) instead of a directly
  fronted private API Gateway.
- **Auth:** Amazon Cognito hosted UI resolves at the `auth-fips` host in
  GovCloud (not `auth`).
- **Model path:** the GovCloud variant uses the same Amazon Bedrock Converse
  path as the commercial mainline, against the FIPS endpoint
  (`bedrock-runtime-fips.<region>.api.aws`) with an entitled model or a GovCloud
  cross-region inference profile (CRIS). The model is a deploy-time parameter, so
  only the model/profile ID and the FIPS endpoint change. (If an account's Claude
  Marketplace agreement is fraud-held and cannot be re-established, the same
  parameter can point the loop at an alternative entitled model; that is an
  account-state workaround, not a GovCloud requirement, and is out of scope for
  this pattern.)
- **Encryption:** the Athena workgroup uses `SSE_S3` (SSE_KMS requires an
  explicit CMK ARN in GovCloud).
- **CDK bootstrap:** the LZA-managed CDKToolkit uses a private bootstrap
  qualifier; set it in `cdk.json` rather than relying on the default `hnb659fds`.
- **VPC egress:** add interface endpoints only for services the LZA does not
  already provision (check `describe-vpc-endpoints` first to avoid a conflicting
  private-DNS domain).
