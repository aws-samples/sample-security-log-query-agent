// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// Infrastructure tests for the two stacks, run with Node's built-in test runner:
//   npm test
// `npm test` compiles with tsc first and runs the compiled tests, so the stacks under
// test are always built from the current sources. The bundling test runs pip, so it
// needs network access to PyPI (or Docker).

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { LogQueryStack, LogQueryStackProps } from '../lib/logquery-stack';
import { LogArchiveGrantStack } from '../lib/logarchive-grant-stack';

const REPO_ROOT = path.join(__dirname, '..');
const QUERY_ACCOUNT = '333333333333';
const LOG_ARCHIVE_ACCOUNT = '444444444444';
const REGION = 'us-west-2';
const VPCE = 'vpce-0123456789abcdef0';
// A non-LZA bucket name, to prove both stacks follow the parameter.
const CENTRAL_BUCKET = `aws-controltower-logs-${LOG_ARCHIVE_ACCOUNT}-${REGION}`;

function queryProps(overrides: Partial<LogQueryStackProps> = {}): LogQueryStackProps {
  return {
    env: { account: QUERY_ACCOUNT, region: REGION },
    queryAccount: QUERY_ACCOUNT,
    logArchiveAccount: LOG_ARCHIVE_ACCOUNT,
    region: REGION,
    modelId: 'us.anthropic.claude-sonnet-5',
    glueDatabase: 'security_central_logs',
    glueCatalogName: 'security_central_logs_catalog',
    workgroupName: 'securitylogagent-wg',
    roleName: 'securitylogagent-exec-role',
    oidcIssuer: 'https://issuer.example.com',
    oidcAudience: 'api://security-log-query',
    requiredGroup: 'SecurityAnalysts',
    apiResourcePolicySourceVpce: VPCE,
    centralBucketName: CENTRAL_BUCKET,
    bytesScannedCutoffPerQuery: 10_737_418_240,
    ...overrides,
  };
}

/** Synthesizes the app stack. Bundling is skipped unless `bundle` is true. */
function synthQueryStack(overrides: Partial<LogQueryStackProps> = {}, bundle = false) {
  const outdir = fs.mkdtempSync(path.join(os.tmpdir(), 'slqa-test-'));
  const context = bundle ? {} : { 'aws:cdk:bundling-stacks': [] };
  const app = new cdk.App({ outdir, context });
  const stack = new LogQueryStack(app, 'SecurityLogQuery-App', queryProps(overrides));
  const template = Template.fromStack(stack);
  return { template, outdir };
}

function statementsWithSid(template: Template, sid: string): any[] {
  const found: any[] = [];
  for (const policy of Object.values(template.findResources('AWS::IAM::Policy'))) {
    for (const statement of (policy as any).Properties.PolicyDocument.Statement) {
      if (statement.Sid === sid) {
        found.push(statement);
      }
    }
  }
  return found;
}

function joinedArn(value: any): string {
  // CDK renders partition-aware ARNs as Fn::Join; flatten to a comparable string.
  if (typeof value === 'string') {
    return value;
  }
  return value['Fn::Join'][1].map((part: any) => (typeof part === 'string' ? part : '<partition>')).join('');
}

function functionAssetDir(template: Template, outdir: string, handler: string): string {
  const fn = Object.values(template.findResources('AWS::Lambda::Function')).find(
    (resource: any) => resource.Properties.Handler === handler,
  ) as any;
  assert.ok(fn, `function with handler ${handler} not found`);
  // The deployed object key is "<asset hash>.zip"; the staged directory is "asset.<hash>".
  const assetHash = String(fn.Properties.Code.S3Key).replace(/\.zip$/, '');
  const dir = path.join(outdir, `asset.${assetHash}`);
  assert.ok(fs.existsSync(dir), `staged asset ${dir} not found`);
  return dir;
}

test('api-handler function finishes inside the API Gateway integration timeout', () => {
  const { template } = synthQueryStack();
  const fn = Object.values(template.findResources('AWS::Lambda::Function')).find(
    (resource: any) => resource.Properties.Handler === 'api_handler.handler',
  ) as any;
  const timeout = fn.Properties.Timeout;
  const deadline = Number(fn.Properties.Environment.Variables.RESPONSE_DEADLINE_SECONDS);
  assert.ok(timeout <= 29, `timeout ${timeout}s exceeds the 29s integration timeout`);
  assert.ok(deadline < timeout, `deadline ${deadline}s is not below the ${timeout}s timeout`);
});

test('private API accepts requests only through the supplied VPC endpoint', () => {
  const { template } = synthQueryStack();
  template.hasResourceProperties('AWS::ApiGateway::RestApi', {
    EndpointConfiguration: { Types: ['PRIVATE'] },
    Policy: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Effect: 'Deny',
          Condition: { StringNotEquals: { 'aws:SourceVpce': VPCE } },
        }),
      ]),
    },
  });
  const api = Object.values(template.findResources('AWS::ApiGateway::RestApi'))[0] as any;
  // aws:PrincipalOrgID is absent for bearer-token callers, so it must not be relied on here.
  assert.ok(!JSON.stringify(api.Properties.Policy).includes('aws:PrincipalOrgID'));
});

test('agent role reads the configured central log bucket, not a hardcoded name', () => {
  const { template } = synthQueryStack();
  const [statement] = statementsWithSid(template, 'CrossAccountLogRead');
  const resources = statement.Resource.map(joinedArn);
  assert.deepEqual(resources, [
    `arn:<partition>:s3:::${CENTRAL_BUCKET}`,
    `arn:<partition>:s3:::${CENTRAL_BUCKET}/*`,
  ]);
});

test('grant stack catalogs and grants the same configured bucket', () => {
  const app = new cdk.App({ context: { 'aws:cdk:bundling-stacks': [] } });
  const stack = new LogArchiveGrantStack(app, 'SecurityLogQuery-LogArchiveGrants', {
    env: { account: LOG_ARCHIVE_ACCOUNT, region: REGION },
    orgId: 'o-abcd123456',
    queryAccount: QUERY_ACCOUNT,
    logArchiveAccount: LOG_ARCHIVE_ACCOUNT,
    region: REGION,
    roleName: 'securitylogagent-exec-role',
    glueDatabase: 'security_central_logs',
    centralBucketName: CENTRAL_BUCKET,
  });
  const template = Template.fromStack(stack);
  template.hasResourceProperties('AWS::Glue::Database', {
    DatabaseInput: { LocationUri: `s3://${CENTRAL_BUCKET}/` },
  });
  const bucketPolicyOutput = template.findOutputs('AddToCentralLogBucketPolicy');
  assert.ok(JSON.stringify(bucketPolicyOutput).includes(CENTRAL_BUCKET));
});

test('Athena workgroup enforces a per-query scan cutoff', () => {
  const { template } = synthQueryStack({ bytesScannedCutoffPerQuery: 1_073_741_824 });
  template.hasResourceProperties('AWS::Athena::WorkGroup', {
    WorkGroupConfiguration: {
      EnforceWorkGroupConfiguration: true,
      BytesScannedCutoffPerQuery: 1_073_741_824,
    },
  });
});

test('Athena workgroup can be deleted after queries have run', () => {
  // Found in the sandbox teardown: DeleteWorkGroup fails with "is not empty" once
  // the workgroup has query history, unless RecursiveDeleteOption is set.
  const { template } = synthQueryStack();
  template.hasResourceProperties('AWS::Athena::WorkGroup', { RecursiveDeleteOption: true });
});

test('Athena results expire and old versions are not kept', () => {
  const { template } = synthQueryStack();
  template.hasResourceProperties('AWS::S3::Bucket', {
    LifecycleConfiguration: {
      Rules: Match.arrayWith([
        Match.objectLike({ Id: 'ExpireQueryResults', ExpirationInDays: 7, NoncurrentVersionExpiration: Match.anyValue() }),
      ]),
    },
  });
});

test('agent role can stop the Athena queries it starts', () => {
  const { template } = synthQueryStack();
  const [statement] = statementsWithSid(template, 'AthenaQuery');
  assert.ok(statement.Action.includes('athena:StopQueryExecution'));
});

test('KMS decrypt is scoped to the supplied key and to calls through S3', () => {
  const keyArn = `arn:aws:kms:${REGION}:${LOG_ARCHIVE_ACCOUNT}:key/11111111-2222-3333-4444-555555555555`;
  const { template } = synthQueryStack({ centralLogKmsKeyArn: keyArn });
  const [statement] = statementsWithSid(template, 'CrossAccountLogKmsDecrypt');
  assert.equal(statement.Resource, keyArn);
  assert.deepEqual(statement.Condition, { StringEquals: { 'kms:ViaService': `s3.${REGION}.amazonaws.com` } });
});

test('both function log groups have a retention period', () => {
  const { template } = synthQueryStack();
  const groups = Object.values(template.findResources('AWS::Logs::LogGroup')) as any[];
  assert.equal(groups.length, 2);
  for (const group of groups) {
    assert.equal(group.Properties.RetentionInDays, 365);
  }
});

test('bundled function packages contain their Python dependencies', () => {
  const { template, outdir } = synthQueryStack({}, true);
  const apiAsset = functionAssetDir(template, outdir, 'api_handler.handler');
  const authorizerAsset = functionAssetDir(template, outdir, 'authorizer.handler');
  assert.ok(fs.existsSync(path.join(apiAsset, 'api_handler.py')));
  assert.ok(fs.existsSync(path.join(apiAsset, 'sqlglot', '__init__.py')), 'sqlglot missing from api-handler package');
  assert.ok(fs.existsSync(path.join(authorizerAsset, 'jwt', '__init__.py')), 'PyJWT missing from authorizer package');
  assert.ok(
    fs.existsSync(path.join(authorizerAsset, 'cryptography', '__init__.py')),
    'cryptography missing from authorizer package',
  );
  assert.ok(!fs.existsSync(path.join(apiAsset, '__pycache__')), 'local bytecode cache was packaged');
});

function synthApp(extraContext: Record<string, string>) {
  const context = {
    queryAccount: QUERY_ACCOUNT,
    logArchiveAccount: LOG_ARCHIVE_ACCOUNT,
    region: REGION,
    orgId: 'o-abcd123456',
    oidcIssuer: 'https://issuer.example.com',
    oidcAudience: 'api://security-log-query',
    requiredGroup: 'SecurityAnalysts',
    apiResourcePolicySourceVpce: VPCE,
    'aws:cdk:bundling-stacks': [],
    ...extraContext,
  };
  const outdir = fs.mkdtempSync(path.join(os.tmpdir(), 'slqa-app-'));
  // `npm test` compiles first, so bin/app.js is built from the current sources.
  return spawnSync(
    process.execPath,
    [path.join(REPO_ROOT, 'bin', 'app.js')],
    {
      cwd: REPO_ROOT,
      env: { ...process.env, CDK_CONTEXT_JSON: JSON.stringify(context), CDK_OUTDIR: outdir },
      encoding: 'utf8',
    },
  );
}

test('the app synthesizes cleanly, including cdk-nag, for accounts other than the examples', () => {
  const result = synthApp({});
  assert.equal(result.status, 0, `synth failed:\n${result.stderr}`);
});

test('the app refuses to synthesize without the API VPC endpoint', () => {
  const result = synthApp({ apiResourcePolicySourceVpce: '' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /apiResourcePolicySourceVpce/);
});
