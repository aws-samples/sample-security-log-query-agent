# Sample: Security Log Query Agent

Query a centralized security log archive in plain English. An analyst asks a
natural-language question ("show me failed console logins in the last 24 hours"),
a foundation model turns it into a **safe, read-only Athena SQL query**, runs it
against the org's centralized security logs, and returns a plain-English summary
of the rows plus the exact SQL it ran.

The reference implementation targets an AWS Landing Zone Accelerator (LZA) /
AWS Control Tower landing zone with centralized log delivery to a dedicated
Log Archive account, and uses the **Amazon Bedrock Converse API with tool use**
so it is **model-agnostic**: the model is a single deploy-time parameter (either
a bare model ID or an inference-profile ID) and the same code drives multiple
model families.

> **This is an AWS sample.** It is published as a reference implementation of an
> AWS Prescriptive Guidance pattern. It is intended for learning and as a
> starting point, not as a production-hardened, drop-in solution. Review the
> IAM, network, and data controls against your own security requirements before
> using it with real data.

---

## What it does

```
Analyst question:  "Which source IPs had the most REJECTED VPC flows yesterday?"
        |
        v
  Foundation model (via Bedrock Converse + tool use) generates ONE read-only Athena query
        |
        v
  Athena runs it against the cross-account central log catalog
        |
        v
  Model summarizes the returned rows in plain English + returns the SQL it ran
```

### Four log sources, queryable out of the box

| Glue table | Source | Example questions |
|---|---|---|
| `cloudtrail` | Organization CloudTrail | failed logins, root usage, `AssumeRole` events, API calls by IP |
| `vpc_flow_logs` | VPC Flow Logs | rejected connections, top talkers, traffic to a port |
| `guardduty` | Amazon GuardDuty findings | active findings by severity, finding types, affected resources |
| `network_firewall` | AWS Network Firewall flow/alert logs | blocked flows, alert signatures, traffic by domain |

All four are delivered natively to the LZA central log bucket, so no extra log
plumbing is required beyond standard LZA / Control Tower centralized logging.

---

## Architecture (at a glance)

```
Analyst
  |  (OIDC login -> JWT with group claim)
  v
[ Edge: OIDC group gate ]              layer 1 -- edge authorization
  |
  v
[ API Handler Lambda ]                 the Converse tool-use agent loop
  |   (securitylogagent-exec-role)     layer 2 -- read-only IAM isolation
  |
  +--> [ Amazon Bedrock Converse ]     model-agnostic; model id OR inference profile
  |
  v
[ Athena (locked-down workgroup: securitylogagent-wg) ]
  |
  v
[ Cross-account Glue Data Catalog + S3 central logs ]   layer 3 -- data controls
        (Log Archive account: security_central_logs database)
        S3 bucket policy + Glue catalog resource policy + KMS grant; NO Lake Formation
```

Full detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### Three enforcement layers

1. **Edge** — the request path validates an OIDC JWT and requires membership in a
   designated security group claim before the query Lambda is ever reached.
2. **IAM** — the agent runs as `securitylogagent-exec-role`, disjoint from any
   other role, with **no write permissions anywhere**.
3. **Data** — read-only is enforced three ways: the handler rejects any
   non-`SELECT`/`WITH` SQL, the Athena workgroup is locked down, and
   cross-account access is granted only via a scoped S3 bucket policy + Glue
   catalog resource policy + KMS decrypt grant. **No Lake Formation** (keeps the
   pattern portable, including to partitions where Lake Formation is
   unavailable).

---

## Model-agnostic by design

The agent uses the **Bedrock Converse API** with a single `run_athena_query`
tool. The model ID is one deploy-time context parameter, so the same code runs
against any Converse-compatible, tool-use-capable model:

- **Amazon Nova** (e.g. `amazon.nova-pro-v1:0`) works by bare model ID.
- **Anthropic Claude** current models are **not** invocable by bare model ID
  on-demand — they require a cross-Region **inference profile** ID (e.g.
  `us.anthropic.claude-sonnet-4-5-20250929-v1:0`). Converse's `modelId` accepts a
  bare model ID **or** an inference-profile ID/ARN transparently. See
  [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) and
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the exact finding and fix.

---

## Commercial mainline + GovCloud / IL5 variant

- **Commercial mainline (this repo's default):** private API Gateway with an
  OIDC authorizer for ingress, `bedrock-runtime` Converse with an entitled model
  or inference profile, standard commercial partition ARNs.
- **GovCloud / IL5 variant:** a Cloud Native Access Point (CNAP) ingress
  (public ALB + WAF -> Transit Gateway -> Network Firewall inspection ->
  internal ALB), Amazon Cognito `auth-fips` hosted UI for OIDC, and the same
  Amazon Bedrock Converse path against the FIPS endpoint
  (`bedrock-runtime-fips`) with an entitled model or GovCloud cross-region
  inference profile (CRIS). The GovCloud data plane uses `SSE_S3` for the Athena
  workgroup and a private CDK bootstrap qualifier. See the "GovCloud / IL5
  variant" section of [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Quickstart

```bash
npm install
npm run build

# 1) Grants in the Log Archive account (Glue DB/tables + catalog resource policy)
npx cdk deploy SecurityLogQuery-LogArchiveGrants \
  -c logArchiveAccount=<LOG_ARCHIVE_ACCOUNT> \
  -c queryAccount=<QUERY_ACCOUNT> \
  -c orgId=<ORG_ID> \
  -c region=us-east-1

# 2) Add the two emitted statements (AddToCentralLogBucketPolicy,
#    AddToCentralLogKmsKeyPolicy) to the LZA-managed central-log bucket + KMS
#    key policies IN THE LZA CONFIG, then run the LZA pipeline so the grants
#    apply (see docs/DEPLOYMENT.md -- attaching them out of band gets reverted).

# 3) The app itself in the query account
npx cdk deploy SecurityLogQuery-App \
  -c queryAccount=<QUERY_ACCOUNT> \
  -c logArchiveAccount=<LOG_ARCHIVE_ACCOUNT> \
  -c region=us-east-1 \
  -c modelId=us.anthropic.claude-sonnet-4-5-20250929-v1:0
```

Full runbook, prerequisites, and the smoke test are in
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

---

## Prerequisites (summary)

- Node 20+, AWS CDK v2, Python 3.12 (Lambda runtime).
- An LZA / Control Tower landing zone delivering CloudTrail, VPC Flow Logs,
  GuardDuty, and Network Firewall logs to a central S3 bucket in a Log Archive
  account.
- Bedrock model access for your chosen model (note the inference-profile
  requirement for current Claude models — `aws bedrock list-inference-profiles`).
- Access to both the query account (app) and the Log Archive account (grants).

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for the full list.

---

## Repository layout

```
.
├── bin/                    # CDK app entry; wires the two stacks + context params
├── lib/                    # CDK stacks (app stack + Log Archive grant stack)
├── lambda/                 # Lambda source (agent loop, authorizer)
├── docs/
│   ├── ARCHITECTURE.md     # Deep dive: flows, Converse loop, IAM, data controls, IL5 variant
│   └── DEPLOYMENT.md       # Step-by-step deploy runbook + prerequisites + smoke test
├── LICENSE                 # MIT-0
├── NOTICE
├── CONTRIBUTING.md
└── .gitignore
```

---

## Security

See [CONTRIBUTING.md](CONTRIBUTING.md#security-issue-notifications) for how to
report a potential security issue. Do **not** create a public GitHub issue for
security findings.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
