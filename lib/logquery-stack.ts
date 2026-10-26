// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as athena from 'aws-cdk-lib/aws-athena';
import * as path from 'path';

export interface LogQueryStackProps extends cdk.StackProps {
  /** Account that hosts the query API and the read-only agent role (this stack's account). */
  readonly queryAccount: string;
  /** Landing Zone Log Archive account that owns the central log bucket, Glue catalog, and CMK. */
  readonly logArchiveAccount: string;
  /** Region for all resources and ARNs. */
  readonly region: string;
  /** AWS Organizations id (o-xxxx); scopes the private API resource policy to the org. */
  readonly orgId: string;
  /** Bedrock model id (usually a cross-region inference profile id, e.g. us.anthropic.claude-sonnet-4-5-...). */
  readonly modelId: string;
  /** Glue database in the Log Archive catalog holding the central-log tables. */
  readonly glueDatabase: string;
  /** Athena DataCatalog name registered in this account for the cross-account Glue catalog. */
  readonly glueCatalogName: string;
  /** Locked-down Athena workgroup name. */
  readonly workgroupName: string;
  /** Read-only agent execution role name. */
  readonly roleName: string;
  /** OIDC issuer URL the authorizer validates tokens against. */
  readonly oidcIssuer: string;
  /** OIDC audience the authorizer requires. */
  readonly oidcAudience: string;
  /** Group claim the caller must carry to be authorized. */
  readonly requiredGroup: string;
  /** Optional VPC endpoint id: when set, the private API resource policy is restricted to it. */
  readonly apiResourcePolicySourceVpce?: string;
}

/**
 * Security Log Query Agent - main application stack (COMMERCIAL MAINLINE variant).
 *
 * A read-only, natural-language security-log query agent deployed INTO the query/app
 * account. Request flow:
 *
 *   private regional REST API Gateway (resource-policy restricted)
 *     -> TOKEN Lambda authorizer (OIDC issuer/audience + required group claim)
 *       -> api-handler Lambda (read-only exec role)
 *          -> Bedrock Converse (tool-use) generates SQL, then runs it via Athena
 *             -> Athena locked-down workgroup + cross-account Glue Data Catalog
 *                -> cross-account read of the Landing Zone central log bucket (Log Archive).
 *
 * Three enforcement layers hold: edge (OIDC + group claim at the authorizer), IAM
 * (a read-only role with no write actions on the log data, scoped to the workgroup/catalog/bucket/key),
 * and data (locked-down Athena workgroup + cross-account bucket/Glue resource policies).
 * Lake Formation is intentionally not used (unavailable in the GovCloud/IL5 variant, so
 * the pattern stays partition-portable).
 *
 * This mainline is deliberately the SIMPLE ingress: a private API Gateway reached over a
 * VPC endpoint, with no public surface. The GovCloud/IL5 hardening variant (documented
 * separately, not built here) fronts this same API with a DoD CNAP path -- internet/DISN
 * ingress -> internal ALB + WAF -> execute-api VPC endpoint -> this private API -- and runs
 * the same Bedrock Converse call against the FIPS endpoint with an entitled model or a
 * cross-region inference profile. Those constructs (ALB, WAF, VPC attachment) live in the
 * variant docs, not in this stack.
 */
export class LogQueryStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: LogQueryStackProps) {
    super(scope, id, props);

    const logArchive = props.logArchiveAccount;

    // ---- Server access log bucket for the Athena results bucket ----
    const accessLogsBucket = new s3.Bucket(this, 'AthenaResultsAccessLogs', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // ---- Athena query-results bucket (SSE-S3, no public access, TLS enforced) ----
    const resultsBucket = new s3.Bucket(this, 'AthenaResults', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      serverAccessLogsBucket: accessLogsBucket,
      serverAccessLogsPrefix: 'athena-results-access/',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // ---- Locked-down Athena workgroup (data-layer control) ----
    // enforceWorkGroupConfiguration=true forces every query to this result location and
    // encryption, so a caller cannot redirect output or disable encryption.
    const workgroup = new athena.CfnWorkGroup(this, 'LogAgentWorkgroup', {
      name: props.workgroupName,
      state: 'ENABLED',
      workGroupConfiguration: {
        enforceWorkGroupConfiguration: true,
        publishCloudWatchMetricsEnabled: true,
        resultConfiguration: {
          outputLocation: `s3://${resultsBucket.bucketName}/results/`,
          encryptionConfiguration: { encryptionOption: 'SSE_S3' },
        },
      },
    });

    // ---- Cross-account Athena DataCatalog registering the Log Archive account's Glue
    // catalog, so Athena in this account can resolve the central-log tables. The Glue
    // resource policy in the Log Archive account grants this role read access. ----
    const dataCatalog = new athena.CfnDataCatalog(this, 'LogArchiveDataCatalog', {
      name: props.glueCatalogName,
      type: 'GLUE',
      parameters: { 'catalog-id': logArchive },
    });

    // ---- Read-only agent execution role (no write actions on the log data) ----
    // The role has read-only access to the log sources (Glue catalog, central log
    // bucket, CMK) and Athena query actions. The only read/write grant is on the
    // private, transient Athena results-staging bucket below, which holds no source
    // log data and is fully reproducible by re-running the query.
    const logRole = new iam.Role(this, 'LogAgentExecRole', {
      roleName: props.roleName,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // Athena: read-only query lifecycle, scoped to this workgroup and data catalog only.
    logRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AthenaQuery',
      actions: [
        'athena:StartQueryExecution',
        'athena:GetQueryExecution',
        'athena:GetQueryResults',
        'athena:GetWorkGroup',
        'athena:GetDataCatalog',
      ],
      resources: [
        `arn:${this.partition}:athena:${this.region}:${this.account}:workgroup/${props.workgroupName}`,
        `arn:${this.partition}:athena:${this.region}:${this.account}:datacatalog/${props.glueCatalogName}`,
      ],
    }));

    // Cross-account Glue catalog metadata (read-only) in the Log Archive account.
    logRole.addToPolicy(new iam.PolicyStatement({
      sid: 'CrossAccountGlueCatalog',
      actions: [
        'glue:GetDatabase', 'glue:GetDatabases',
        'glue:GetTable', 'glue:GetTables',
        'glue:GetPartition', 'glue:GetPartitions',
      ],
      resources: [
        `arn:${this.partition}:glue:${this.region}:${logArchive}:catalog`,
        `arn:${this.partition}:glue:${this.region}:${logArchive}:database/${props.glueDatabase}`,
        `arn:${this.partition}:glue:${this.region}:${logArchive}:table/${props.glueDatabase}/*`,
      ],
    }));

    // Cross-account read of the central log bucket ONLY (no other buckets).
    logRole.addToPolicy(new iam.PolicyStatement({
      sid: 'CrossAccountLogRead',
      actions: ['s3:GetObject', 's3:ListBucket'],
      resources: [
        `arn:${this.partition}:s3:::aws-accelerator-central-logs-${logArchive}-${this.region}`,
        `arn:${this.partition}:s3:::aws-accelerator-central-logs-${logArchive}-${this.region}/*`,
      ],
    }));

    // Central log objects are SSE-KMS with the LZA central-log CMK (in Log Archive).
    // Decrypt only; the key policy in the Log Archive account grants this role.
    logRole.addToPolicy(new iam.PolicyStatement({
      sid: 'CrossAccountLogKmsDecrypt',
      actions: ['kms:Decrypt', 'kms:DescribeKey'],
      resources: [`arn:${this.partition}:kms:${this.region}:${logArchive}:key/*`],
    }));

    // Results bucket read/write for query output staging.
    resultsBucket.grantReadWrite(logRole);

    // Bedrock: invoke the model plus inference profiles. Claude REQUIRES an inference
    // profile (on-demand throughput is unsupported), so both the account-scoped profile
    // ARNs and the cross-region system-defined foundation-model profile ARNs are granted.
    logRole.addToPolicy(new iam.PolicyStatement({
      sid: 'BedrockInvoke',
      actions: ['bedrock:InvokeModel'],
      resources: [
        `arn:${this.partition}:bedrock:${this.region}:${this.account}:inference-profile/*`,
        `arn:${this.partition}:bedrock:*::foundation-model/*`,
      ],
    }));

    // ---- api-handler Lambda: the DIY agent loop (Bedrock Converse tool-use -> Athena) ----
    const apiHandler = new lambda.Function(this, 'ApiHandler', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'api_handler.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'lambda', 'api-handler')),
      role: logRole,
      timeout: cdk.Duration.seconds(120),
      memorySize: 512,
      environment: {
        MODEL_ID: props.modelId,
        ATHENA_WORKGROUP: props.workgroupName,
        GLUE_CATALOG_NAME: props.glueCatalogName,
        GLUE_DATABASE: props.glueDatabase,
        MAX_TOOL_TURNS: '6',
      },
    });

    // ---- authorizer Lambda: OIDC issuer/audience + required group claim ----
    const authorizerFn = new lambda.Function(this, 'LogAgentAuthorizer', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'authorizer.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'lambda', 'authorizer')),
      timeout: cdk.Duration.seconds(10),
      environment: {
        OIDC_ISSUER: props.oidcIssuer,
        OIDC_AUDIENCE: props.oidcAudience,
        REQUIRED_GROUP: props.requiredGroup,
      },
    });

    // ---- Private regional REST API Gateway ----
    // Private REST APIs REQUIRE a resource policy. The Allow statement is always scoped to
    // the organization (aws:PrincipalOrgID), so callers outside the org are denied even on
    // the default path. When a source VPC endpoint id is also provided, invocation is
    // further restricted to that endpoint via an explicit Deny.
    const orgCondition = { StringEquals: { 'aws:PrincipalOrgID': props.orgId } };
    const resourcePolicy = props.apiResourcePolicySourceVpce
      ? new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.DENY,
              principals: [new iam.AnyPrincipal()],
              actions: ['execute-api:Invoke'],
              resources: ['execute-api:/*'],
              conditions: {
                StringNotEquals: { 'aws:SourceVpce': props.apiResourcePolicySourceVpce },
              },
            }),
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              principals: [new iam.AnyPrincipal()],
              actions: ['execute-api:Invoke'],
              resources: ['execute-api:/*'],
              conditions: orgCondition,
            }),
          ],
        })
      : new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              principals: [new iam.AnyPrincipal()],
              actions: ['execute-api:Invoke'],
              resources: ['execute-api:/*'],
              conditions: orgCondition,
            }),
          ],
        });

    const api = new apigw.RestApi(this, 'LogAgentApi', {
      restApiName: `${id}-api`,
      endpointConfiguration: { types: [apigw.EndpointType.PRIVATE] },
      deployOptions: { stageName: 'prod' },
      policy: resourcePolicy,
    });

    const authorizer = new apigw.TokenAuthorizer(this, 'LogAgentTokenAuthorizer', {
      handler: authorizerFn,
      identitySource: apigw.IdentitySource.header('Authorization'),
      resultsCacheTtl: cdk.Duration.minutes(5),
    });

    const query = api.root.addResource('query');
    query.addMethod('POST', new apigw.LambdaIntegration(apiHandler), {
      authorizationType: apigw.AuthorizationType.CUSTOM,
      authorizer,
    });

    // ---- Outputs ----
    new cdk.CfnOutput(this, 'ApiUrl', { value: api.url });
    new cdk.CfnOutput(this, 'WorkgroupName', { value: workgroup.name });
    new cdk.CfnOutput(this, 'LogAgentRoleArn', { value: logRole.roleArn });
    new cdk.CfnOutput(this, 'ApiId', { value: api.restApiId });

    // Keep the data catalog dependency explicit so the workgroup/role resolve names it registers.
    dataCatalog.node.addDependency(workgroup);
  }
}
