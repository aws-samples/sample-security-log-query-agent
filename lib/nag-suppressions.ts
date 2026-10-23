import { Stack, Validations } from 'aws-cdk-lib';

/**
 * cdk-nag suppressions for the reference sample, each with a standalone technical
 * justification. These record deliberate design choices for a minimal, model-agnostic
 * reference implementation; a production deployment reviews and tightens them against
 * its own security requirements (as the README states).
 */
export function applyNagSuppressions(queryStack: Stack, grantStack: Stack): void {
  const iam4Reason =
    'AWSLambdaBasicExecutionRole (and the API Gateway CloudWatch push policy) provide ' +
    'only CloudWatch Logs write for the function/stage log group. They grant no ' +
    'data-plane access and are the standard least-privilege execution policies.';
  const iam5Reason =
    'The read-only agent role is scoped by resource ARN to the single Athena workgroup, ' +
    'the cross-account Glue catalog/database, the one central log bucket, the log CMK, ' +
    'and inference-profile ARNs. The remaining wildcards are object-level (bucket/*, ' +
    'table/*, key/*, inference-profile/*) or read-action families (s3:Get*/List*) on ' +
    'those scoped resources; no write or delete action is granted on the log data. The ' +
    'results-bucket read/write wildcard is on a private, transient Athena staging bucket.';
  const l1Reason =
    'The Lambda runtime pins Python 3.12 for reproducibility of this reference; a ' +
    'production deployment tracks the latest supported runtime on its own cadence.';

  const queryAcks: { id: string; reason: string }[] = [
    { id: 'AwsSolutions-L1', reason: l1Reason },
    {
      id: 'AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole]',
      reason: iam4Reason,
    },
    {
      id: 'AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs]',
      reason: iam4Reason,
    },
    { id: 'AwsSolutions-IAM5[Action::s3:Abort*]', reason: iam5Reason },
    { id: 'AwsSolutions-IAM5[Action::s3:DeleteObject*]', reason: iam5Reason },
    { id: 'AwsSolutions-IAM5[Action::s3:GetBucket*]', reason: iam5Reason },
    { id: 'AwsSolutions-IAM5[Action::s3:GetObject*]', reason: iam5Reason },
    { id: 'AwsSolutions-IAM5[Action::s3:List*]', reason: iam5Reason },
    { id: 'AwsSolutions-IAM5[Resource::<AthenaResults99A60126.Arn>/*]', reason: iam5Reason },
    {
      id: 'AwsSolutions-IAM5[Resource::arn:<AWS::Partition>:bedrock:*::foundation-model/*]',
      reason: iam5Reason,
    },
    {
      id: 'AwsSolutions-IAM5[Resource::arn:<AWS::Partition>:bedrock:us-east-1:111111111111:inference-profile/*]',
      reason: iam5Reason,
    },
    {
      id: 'AwsSolutions-IAM5[Resource::arn:<AWS::Partition>:glue:us-east-1:222222222222:table/security_central_logs/*]',
      reason: iam5Reason,
    },
    {
      id: 'AwsSolutions-IAM5[Resource::arn:<AWS::Partition>:kms:us-east-1:222222222222:key/*]',
      reason: iam5Reason,
    },
    {
      id: 'AwsSolutions-IAM5[Resource::arn:<AWS::Partition>:s3:::aws-accelerator-central-logs-222222222222-us-east-1/*]',
      reason: iam5Reason,
    },
    {
      id: 'NIST.800.53.R5-IAMNoInlinePolicy',
      reason:
        'The role uses inline policies to keep each least-privilege grant colocated ' +
        'with the construct that needs it, so the scoping is auditable in one place ' +
        'in this reference. A production deployment may convert these to managed policies.',
    },
    {
      id: 'NIST.800.53.R5-LambdaInsideVPC',
      reason:
        'The reference deploys the Lambdas without a VPC to keep the sample minimal and ' +
        'partition-portable. The documented GovCloud/IL5 variant places the functions in ' +
        'a VPC behind the CNAP ingress path.',
    },
    {
      id: 'NIST.800.53.R5-LambdaDLQ',
      reason:
        'The API-handler and authorizer are synchronous request/response functions; a ' +
        'failure surfaces to the caller rather than being retried asynchronously, so a ' +
        'dead-letter queue does not apply. A production deployment adds one if it moves to async.',
    },
    {
      id: 'NIST.800.53.R5-LambdaConcurrency',
      reason:
        'Reserved concurrency is a per-account capacity decision left to the deploying ' +
        'team; the reference does not pin a limit so it does not starve other functions ' +
        'in the account it is dropped into.',
    },
    {
      id: 'AwsSolutions-COG4',
      reason:
        'Authorization is enforced by a TOKEN Lambda authorizer that validates the OIDC ' +
        'issuer, audience, and required group claim, rather than a Cognito user pool. ' +
        'The pattern targets an external enterprise IdP (e.g. Entra), so a Cognito ' +
        'authorizer does not apply.',
    },
    {
      id: 'AwsSolutions-APIG2',
      reason:
        'Request bodies are validated in the api-handler before use; the single POST ' +
        'method takes a free-text question, so schema-level request validation at the ' +
        'gateway adds no meaningful control for this reference.',
    },
    {
      id: 'AwsSolutions-APIG1',
      reason:
        'Access logging is a per-environment operational choice; the reference leaves the ' +
        'log destination unset so it does not create an unmanaged log group in the target ' +
        'account. A production deployment configures an access log destination.',
    },
    {
      id: 'AwsSolutions-APIG6',
      reason:
        'Method-level CloudWatch logging is a per-environment operational choice; a ' +
        'production deployment enables it against its own log configuration.',
    },
    {
      id: 'AwsSolutions-APIG3',
      reason:
        'The API is a PRIVATE endpoint reachable only through a VPC endpoint and gated by ' +
        'the OIDC authorizer; the documented GovCloud/IL5 variant adds a WAF web ACL on the ' +
        'internet-facing ALB in front of it.',
    },
    {
      id: 'NIST.800.53.R5-APIGWAssociatedWithWAF',
      reason:
        'The API is a PRIVATE endpoint with no public surface; WAF is applied at the ' +
        'internet-facing ALB in the documented GovCloud/IL5 ingress variant.',
    },
    {
      id: 'NIST.800.53.R5-APIGWSSLEnabled',
      reason:
        'This rule targets backend SSL client certificates for API Gateway integrations. ' +
        'The backend integration is a Lambda invoked over the AWS internal control plane ' +
        '(TLS enforced by the service), not an HTTP backend requiring a client certificate.',
    },
    {
      id: 'NIST.800.53.R5-APIGWExecutionLoggingEnabled',
      reason:
        'Execution logging is a per-environment operational choice tied to a log ' +
        'configuration the deploying account owns; a production deployment enables it.',
    },
    {
      id: 'NIST.800.53.R5-APIGWCacheEnabledAndEncrypted',
      reason:
        'Response caching is intentionally disabled: query answers are derived from ' +
        'live security-log data and must not be served from a cache. The rule does not ' +
        'apply when caching is off by design.',
    },
    {
      id: 'NIST.800.53.R5-S3DefaultEncryptionKMS',
      reason:
        'The Athena results bucket uses SSE-S3 to keep the reference free of a customer ' +
        'managed KMS key (which the README notes as a production hardening step). Query ' +
        'results are transient staging output, not the source log data.',
    },
    {
      id: 'NIST.800.53.R5-S3BucketReplicationEnabled',
      reason:
        'The results bucket holds transient Athena query staging output that is fully ' +
        'reproducible by re-running the query, so cross-region replication is unwarranted.',
    },
  ];

  const grantAcks: { id: string; reason: string }[] = [
    {
      id: 'AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole]',
      reason:
        'AWSLambdaBasicExecutionRole on the CDK custom-resource provider grants only ' +
        'CloudWatch Logs write; it is created by the AwsCustomResource construct, not by ' +
        'application code, and carries no data-plane access.',
    },
    {
      id: 'AwsSolutions-IAM5[Resource::*]',
      reason:
        'The wildcard is on the CDK-synthesized custom-resource provider used to put the ' +
        'Glue catalog resource policy. It is generated by the AwsCustomResource construct ' +
        'and scoped to the single Glue PutResourcePolicy call this stack performs.',
    },
    {
      id: 'NIST.800.53.R5-IAMNoInlinePolicy',
      reason:
        'The inline policy belongs to the CDK-synthesized custom-resource provider, ' +
        'generated by the AwsCustomResource construct rather than authored here.',
    },
    {
      id: 'NIST.800.53.R5-LambdaInsideVPC',
      reason:
        'The function is the CDK-synthesized custom-resource provider (AwsCustomResource) ' +
        'that makes one Glue control-plane call; it is not application code and does not ' +
        'touch VPC data-plane resources.',
    },
    {
      id: 'NIST.800.53.R5-LambdaDLQ',
      reason:
        'The function is the CDK-synthesized custom-resource provider; its lifecycle is ' +
        'managed by CloudFormation custom-resource retries, not an application DLQ.',
    },
    {
      id: 'NIST.800.53.R5-LambdaConcurrency',
      reason:
        'The function is the CDK-synthesized custom-resource provider that runs only during ' +
        'stack deploy/delete, so a concurrency limit is unwarranted.',
    },
  ];

  for (const ack of queryAcks) {
    Validations.of(queryStack).acknowledge(ack);
  }
  for (const ack of grantAcks) {
    Validations.of(grantStack).acknowledge(ack);
  }
}
