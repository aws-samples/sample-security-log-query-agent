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
 * Required context:
 *   queryAccount       AWS account the query agent + API run in
 *   logArchiveAccount  AWS account that owns the central log bucket/catalog
 *   region             AWS region for both stacks
 *   orgId              AWS Organizations id (o-xxxx) used to scope cross-account grants
 *   oidcIssuer         OIDC issuer URL (e.g. https://login.microsoftonline.com/<tenant>/v2.0)
 *   oidcAudience       OIDC audience / client id the API tokens are minted for
 *   requiredGroup      group claim the caller must hold to be authorized
 *
 * Optional context (sensible defaults shown):
 *   glueDatabase                security_central_logs
 *   glueCatalogName             security_central_logs_catalog
 *   workgroupName               securitylogagent-wg
 *   roleName                    securitylogagent-exec-role
 *   modelId                     us.anthropic.claude-sonnet-4-5-20250929-v1:0
 *   centralBucketName           (discovered/derived by the grant stack if omitted)
 *   apiResourcePolicySourceVpce (VPCE id to lock the private API resource policy to)
 *
 * Example:
 *   cdk deploy --all \
 *     -c queryAccount=111111111111 -c logArchiveAccount=222222222222 \
 *     -c region=us-east-1 -c orgId=o-abcd1234 \
 *     -c oidcIssuer=https://login.microsoftonline.com/<tenant>/v2.0 \
 *     -c oidcAudience=api://security-log-query -c requiredGroup=SecurityAnalysts
 */

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

// Required.
const queryAccount = requireContext('queryAccount');
const logArchiveAccount = requireContext('logArchiveAccount');
const region = requireContext('region');
const orgId = requireContext('orgId');
const oidcIssuer = requireContext('oidcIssuer');
const oidcAudience = requireContext('oidcAudience');
const requiredGroup = requireContext('requiredGroup');

// Optional overrides with documented defaults.
const glueDatabase = contextOr('glueDatabase', 'security_central_logs');
const glueCatalogName = contextOr('glueCatalogName', 'security_central_logs_catalog');
const workgroupName = contextOr('workgroupName', 'securitylogagent-wg');
const roleName = contextOr('roleName', 'securitylogagent-exec-role');
const modelId = contextOr('modelId', 'us.anthropic.claude-sonnet-4-5-20250929-v1:0');
const centralBucketName = app.node.tryGetContext('centralBucketName') as string | undefined;
const apiResourcePolicySourceVpce = app.node.tryGetContext('apiResourcePolicySourceVpce') as
  | string
  | undefined;

// Main app stack -> query account.
const queryStack = new LogQueryStack(app, 'SecurityLogQuery-App', {
  env: { account: queryAccount, region },
  queryAccount,
  logArchiveAccount,
  region,
  orgId,
  modelId,
  glueDatabase,
  glueCatalogName,
  workgroupName,
  roleName,
  oidcIssuer,
  oidcAudience,
  requiredGroup,
  apiResourcePolicySourceVpce,
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
applyNagSuppressions(queryStack, grantStack);
Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
Validations.of(app).addPlugins(new NIST80053R5Checks(app, { verbose: true }));

app.synth();