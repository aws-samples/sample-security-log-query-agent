# Deployment Runbook

This runbook deploys the Security Log Query Agent onto an AWS Landing Zone
Accelerator (LZA) / AWS Control Tower landing zone. The **commercial mainline**
is the default; a **GovCloud / IL5 variant** is noted where it differs (see also
the "GovCloud / IL5 variant" section of [`ARCHITECTURE.md`](ARCHITECTURE.md)).

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
| Node 20+, AWS CDK v2 | `npm install -g aws-cdk` or use `npx cdk` |
| Python 3.12 | Lambda runtime |
| Query + Log Archive account access | short-lived creds; query account for the app, Log Archive for grants |
| LZA / Control Tower centralized logging | delivering the four sources to the central log bucket (below) |
| Bedrock model access | for your chosen model — **note the inference-profile requirement for current Claude models** (below) |
| CDK bootstrap | both accounts bootstrapped for CDK v2 (see the IL5 variant note on the private bootstrap qualifier) |

### Centralized log delivery (all four sources)

The pattern queries logs already delivered by the LZA to the central log bucket
in the Log Archive account (typically
`aws-accelerator-central-logs-<LOG_ARCHIVE_ACCOUNT>-<region>`). Confirm all four
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
`us.anthropic.claude-sonnet-4-5-20250929-v1:0`). Amazon Nova models work by bare
model ID. List the inference profiles available in your account/region:

```bash
aws bedrock list-inference-profiles --region <region>
```

Pass whichever value you choose to the app stack as `-c modelId=...` — the
Converse `modelId` accepts a bare model ID **or** an inference-profile ID/ARN
transparently.

---

## 1. Build

```bash
npm install
npm run build      # tsc
```

Bundle any authorizer dependencies into the authorizer Lambda asset directory
(pip install into the asset dir, or use a Lambda layer) before deploy. The
api-handler uses only the standard library + `boto3` (present in the Lambda
runtime), so it needs no bundling.

---

## 2. Deploy the Log Archive grants

Run with **Log Archive account** credentials:

```bash
npx cdk deploy SecurityLogQuery-LogArchiveGrants \
  -c logArchiveAccount=<LOG_ARCHIVE_ACCOUNT> \
  -c queryAccount=<QUERY_ACCOUNT> \
  -c orgId=<ORG_ID> \
  -c region=<region>
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
npx cdk deploy SecurityLogQuery-App \
  -c queryAccount=<QUERY_ACCOUNT> \
  -c logArchiveAccount=<LOG_ARCHIVE_ACCOUNT> \
  -c region=<region> \
  -c modelId=us.anthropic.claude-sonnet-4-5-20250929-v1:0
```

Relevant stack outputs include the API endpoint, the Athena workgroup name
(`securitylogagent-wg`), and the agent role ARN
(`securitylogagent-exec-role`).

---

## 5. Smoke test

Invoke the API handler directly (bypasses the edge authorizer for a quick
backend check). Use `--cli-read-timeout 0` because the agent loop can run longer
than the default timeout:

```bash
aws lambda invoke \
  --function-name securitylogagent-apihandler \
  --region <region> \
  --cli-read-timeout 0 \
  --payload '{"body": "{\"question\": \"How many events were logged in the last day?\"}"}' \
  --cli-binary-format raw-in-base64-out \
  /dev/stdout
```

Expected: HTTP 200 with an `answer` string and the `sql` the model ran. Try each
source, e.g. "Which source IPs had the most REJECTED VPC flows yesterday?",
"List active GuardDuty findings by severity", "Show blocked flows from Network
Firewall in the last hour".

End-to-end (through the ingress) requires a valid OIDC JWT carrying the required
security group claim in the `Authorization: Bearer` header, `POST`ed to the
query endpoint with body `{"question": "..."}`.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ValidationException: on-demand throughput isn't supported` | You passed a bare Claude model ID. Use a `us.` inference-profile ID (`aws bedrock list-inference-profiles`). |
| `Query FAILED` from Athena | Glue tables not populated / wrong prefix, or the cross-account grant did not apply. Confirm the grant stack ran and the LZA pipeline applied the S3/KMS statements. |
| Cross-account read denied | The S3/KMS statements were attached out of band and reverted by the LZA. Wire them through the LZA config (step 3) and re-run the pipeline. |
| Authorizer always Deny | JWKS / issuer / audience mismatch, or the token lacks the required security group claim. |
| Access denied on Bedrock | Model access not granted in this account/region, or the region-deny SCP blocks Bedrock. Grant model access and confirm the model/profile is reachable from the query account's region. |

---

## Teardown

```bash
# Query account
npx cdk destroy SecurityLogQuery-App \
  -c queryAccount=<QUERY_ACCOUNT> -c region=<region>

# Log Archive account
npx cdk destroy SecurityLogQuery-LogArchiveGrants \
  -c logArchiveAccount=<LOG_ARCHIVE_ACCOUNT> -c queryAccount=<QUERY_ACCOUNT> -c region=<region>
```

Then remove the two statements you added to the LZA central-log bucket / KMS
policies and run the pipeline once more to reconcile.

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
