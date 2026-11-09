#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks, NIST80053R5Checks } from 'cdk-nag';
import { LogQueryStack } from '../lib/logquery-stack';
import { LogArchiveGrantStack } from '../lib/logarchive-grant-stack';
import { applyNagSuppressions } from '../lib/nag-suppressions';

/**
 * Sample Security Log Query Agent - CDK app entry point.
 *
 * All configuration is supplied via CDK context (`-c key=value`, or cdk.json).
 * Nothing is hardcoded to a specific account, organization, or environment.
 *
 * Both stacks are synthesized on every command, so every required value must be
 * supplied whichever stack you deploy.
 *
 * Required context:
 *   queryAccount                 AWS account the query agent + API run in
 *   logArchiveAccount            AWS account that owns the central log bucket/catalog
 *   region                       AWS region for both stacks
 *   orgId                        AWS Organizations id (o-xxxx) used to scope cross-account grants
 *   oidcIssuer                   OIDC issuer URL (e.g. https://login.microsoftonline.com/<tenant>/v2.0)
 *   oidcAudience                 OIDC audience / client id the API tokens are minted for
 *   requiredGroup                group claim value the caller must hold to be authorized
 *   apiResourcePolicySourceVpce  ID of the execute-api interface VPC endpoint callers use (vpce-...)
 *
 * Optional context (defaults shown):
 *   centralBucketName            aws-accelerator-central-logs-<logArchiveAccount>-<region> (LZA convention)
 *   centralLogKmsKeyArn          (unset: kms:Decrypt on any Log Archive key, via S3 only)
 *   bytesScannedCutoffPerQuery   10737418240 (10 GiB per query; Athena minimum is 10 MB)
 *   modelTemperature             (unset: not sent; some current models reject it)
 *   glueDatabase                 security_central_logs
 *   glueCatalogName              security_central_logs_catalog
 *   workgroupName                securitylogagent-wg
 *   roleName                     securitylogagent-exec-role
 *   modelId                      us.anthropic.claude-sonnet-5
 *
 * Example:
 *   cdk deploy --all \
 *     -c queryAccount=111111111111 -c logArchiveAccount=222222222222 \
 *     -c region=us-east-1 -c orgId=o-abcd1234 \
 *     -c oidcIssuer=https://login.microsoftonline.com/<tenant>/v2.0 \
 *     -c oidcAudience=api://security-log-query -c requiredGroup=SecurityAnalysts \
 *     -c apiResourcePolicySourceVpce=vpce-0123456789abcdef0
 */

const ATHENA_MIN_BYTES_SCANNED_CUTOFF = 10_000_000;

const app = new cdk.App();

function requireContext(key: string): string {
  const value = app.node.tryGetContext(key);
  if (value === undefined || value === null || String(value).trim() === '') {
    throw new Error(
      `Missing required CDK context value '${key}'. ` +
        `Pass it with -c ${key}=<value> or set it in cdk.json.`,
    );
  }
  return String(value);
}

function contextOr(key: string, fallback: string): string {
  const value = app.node.tryGetContext(key);
  return value === undefined || value === null || String(value).trim() === ''
    ? fallback
    : String(value);
}

function requireMatch(key: string, value: string, pattern: RegExp, expected: string): string {
  if (!pattern.test(value)) {
    throw new Error(`CDK context value '${key}' must be ${expected}; got '${value}'.`);
  }
  return value;
}

// Required.
const queryAccount = requireMatch('queryAccount', requireContext('queryAccount'), /^\d{12}$/, 'a 12-digit account ID');
const logArchiveAccount = requireMatch(
  'logArchiveAccount', requireContext('logArchiveAccount'), /^\d{12}$/, 'a 12-digit account ID');
const region = requireContext('region');
const orgId = requireMatch('orgId', requireContext('orgId'), /^o-[a-z0-9]{10,32}$/, 'an organization ID (o-...)');
const oidcIssuer = requireContext('oidcIssuer');
const oidcAudience = requireContext('oidcAudience');
const requiredGroup = requireContext('requiredGroup');
const apiResourcePolicySourceVpce = requireMatch(
  'apiResourcePolicySourceVpce',
  requireContext('apiResourcePolicySourceVpce'),
  /^vpce-[0-9a-f]{8,17}$/,
  'an execute-api interface VPC endpoint ID (vpce-...)',
);

// Optional overrides with documented defaults.
const glueDatabase = contextOr('glueDatabase', 'security_central_logs');
const glueCatalogName = contextOr('glueCatalogName', 'security_central_logs_catalog');
const workgroupName = contextOr('workgroupName', 'securitylogagent-wg');
const roleName = contextOr('roleName', 'securitylogagent-exec-role');
const modelId = contextOr('modelId', 'us.anthropic.claude-sonnet-5');
// One value feeds both stacks: the Glue tables and emitted bucket policy in the Log Archive
// stack, and the read grant on the agent role in the app stack.
const centralBucketName = contextOr(
  'centralBucketName',
  `aws-accelerator-central-logs-${logArchiveAccount}-${region}`,
);
const kmsKeyArnContext = app.node.tryGetContext('centralLogKmsKeyArn');
const centralLogKmsKeyArn =
  kmsKeyArnContext === undefined || kmsKeyArnContext === null || String(kmsKeyArnContext).trim() === ''
    ? undefined
    : requireMatch(
        'centralLogKmsKeyArn',
        String(kmsKeyArnContext),
        new RegExp(`^arn:aws[a-z-]*:kms:${region}:${logArchiveAccount}:key/[0-9a-f-]{36}$`),
        `a KMS key ARN in account ${logArchiveAccount} and region ${region}`,
      );
const temperatureContext = contextOr('modelTemperature', '');
const modelTemperature = temperatureContext === '' ? undefined : Number(temperatureContext);
if (modelTemperature !== undefined && !(modelTemperature >= 0 && modelTemperature <= 1)) {
  throw new Error(`CDK context value 'modelTemperature' must be a number from 0 to 1.`);
}
const bytesScannedCutoffPerQuery = Number(contextOr('bytesScannedCutoffPerQuery', '10737418240'));
if (!Number.isInteger(bytesScannedCutoffPerQuery) || bytesScannedCutoffPerQuery < ATHENA_MIN_BYTES_SCANNED_CUTOFF) {
  throw new Error(
    `CDK context value 'bytesScannedCutoffPerQuery' must be an integer of at least ` +
      `${ATHENA_MIN_BYTES_SCANNED_CUTOFF} bytes.`,
  );
}

// Main app stack -> query account.
const queryStack = new LogQueryStack(app, 'SecurityLogQuery-App', {
  env: { account: queryAccount, region },
  queryAccount,
  logArchiveAccount,
  region,
  modelId,
  glueDatabase,
  glueCatalogName,
  workgroupName,
  roleName,
  oidcIssuer,
  oidcAudience,
  requiredGroup,
  apiResourcePolicySourceVpce,
  centralBucketName,
  centralLogKmsKeyArn,
  bytesScannedCutoffPerQuery,
  modelTemperature,
  description:
    'Security Log Query Agent: private API GW -> OIDC authorizer (group-gated) -> ' +
    'Bedrock (Converse tool-use) -> Athena -> cross-account central S3 logs.',
  tags: { app: 'security-log-query-agent', component: 'query' },
});

// Cross-account grant stack -> log archive account (data owner).
const grantStack = new LogArchiveGrantStack(app, 'SecurityLogQuery-LogArchiveGrants', {
  env: { account: logArchiveAccount, region },
  logArchiveAccount,
  queryAccount,
  region,
  orgId,
  glueDatabase,
  roleName,
  centralBucketName,
  description:
    'Cross-account grants in the log archive account: S3 bucket policy + Glue catalog ' +
    'resource policy + KMS grant scoped to the query account exec role.',
  tags: { app: 'security-log-query-agent', component: 'logarchive-grants' },
});

// Compliance checks (cdk-nag v3). The packs are policy-validation plugins, so they
// register via Validations.of(app).addPlugins(...) (NOT Aspects, which is v2).
// Suppressions are acknowledged first so they are in place when validation runs.
applyNagSuppressions(queryStack, grantStack, {
  queryAccount,
  logArchiveAccount,
  region,
  glueDatabase,
  centralBucketName,
  centralLogKmsKeyArn,
});
Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
Validations.of(app).addPlugins(new NIST80053R5Checks(app, { verbose: true }));

app.synth();