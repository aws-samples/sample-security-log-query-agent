// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as athena from 'aws-cdk-lib/aws-athena';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as path from 'path';
import { PYTHON_ARCHITECTURE, PYTHON_RUNTIME, pythonCode } from './python-bundling';

/**
 * API Gateway REST integration timeout (seconds). The handler finishes inside it;
 * see RESPONSE_DEADLINE_SECONDS in the api-handler.
 */
const API_INTEGRATION_TIMEOUT_SECONDS = 29;

export interface LogQueryStackProps extends cdk.StackProps {
  /** Account that hosts the query API and the read-only agent role (this stack's account). */
  readonly queryAccount: string;
  /** Landing Zone Log Archive account that owns the central log bucket, Glue catalog, and CMK. */
  readonly logArchiveAccount: string;
  /** Region for all resources and ARNs. */
  readonly region: string;
  /** Bedrock model id (usually a cross-region inference profile id, e.g. us.anthropic.claude-sonnet-5). */
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
  /**
   * ID of the existing execute-api interface VPC endpoint that callers use (vpce-...).
   * The private API's resource policy denies every request that does not arrive through it.
   */
  readonly apiResourcePolicySourceVpce: string;
  /** Name of the central log bucket in the Log Archive account. */
  readonly centralBucketName: string;
  /**
   * ARN of the KMS key that encrypts the central log bucket. When set, kms:Decrypt is
   * scoped to that key; otherwise it is granted on any key in the Log Archive account,
   * limited to use through Amazon S3.
   */
  readonly centralLogKmsKeyArn?: string;
  /** Per-query Athena scan limit in bytes (workgroup BytesScannedCutoffPerQuery). */
  readonly bytesScannedCutoffPerQuery: number;
  /**
   * Optional sampling temperature for the model. Omitted from the request when unset,
   * because some current models reject the temperature parameter.
   */
  readonly modelTemperature?: number;
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
 * This mainline is deliberately the SIMPLE ingress: a private API Gateway with no public
 * surface. The stack does not create the execute-api interface VPC endpoint; the deployer
 * supplies an existing one (landing zones usually provision endpoints centrally), and the
 * API resource policy accepts requests only through it. The GovCloud/IL5 hardening variant (documented
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
      lifecycleRules: [
        {
          id: 'ExpireAccessLogs',
          expiration: cdk.Duration.days(90),
          noncurrentVersionExpiration: cdk.Duration.days(1),
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(1),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // ---- Athena query-results bucket (SSE-S3, no public access, TLS enforced) ----
    // Results are copies of log data, so they expire after seven days, and versioning
    // keeps no older copies beyond one day.
    const resultsBucket = new s3.Bucket(this, 'AthenaResults', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      lifecycleRules: [
        {
          id: 'ExpireQueryResults',
          expiration: cdk.Duration.days(7),
          noncurrentVersionExpiration: cdk.Duration.days(1),
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(1),
        },
      ],
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
      // Without this, stack deletion fails once any query has run ("WorkGroup ... is not empty").
      recursiveDeleteOption: true,
      workGroupConfiguration: {
        enforceWorkGroupConfiguration: true,
        publishCloudWatchMetricsEnabled: true,
        // Hard per-query scan ceiling: Athena cancels any query that would read more.
        bytesScannedCutoffPerQuery: props.bytesScannedCutoffPerQuery,
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
        'athena:StopQueryExecution',
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
        `arn:${this.partition}:s3:::${props.centralBucketName}`,
        `arn:${this.partition}:s3:::${props.centralBucketName}/*`,
      ],
    }));

    // Central log objects are SSE-KMS with the landing-zone central-log key (in Log Archive).
    // Decrypt only, and only when Amazon S3 makes the call on the role's behalf; the key
    // policy in the Log Archive account must also grant this role.
    logRole.addToPolicy(new iam.PolicyStatement({
      sid: 'CrossAccountLogKmsDecrypt',
      actions: ['kms:Decrypt', 'kms:DescribeKey'],
      resources: [
        props.centralLogKmsKeyArn ?? `arn:${this.partition}:kms:${this.region}:${logArchive}:key/*`,
      ],
      conditions: { StringEquals: { 'kms:ViaService': `s3.${this.region}.amazonaws.com` } },
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
    // Log groups are explicit so retention is set. The api-handler group is the audit
    // trail (caller, question, SQL, query IDs), so it is retained on stack deletion.
    const apiHandlerLogs = new logs.LogGroup(this, 'ApiHandlerLogs', {
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const authorizerLogs = new logs.LogGroup(this, 'AuthorizerLogs', {
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // ---- api-handler Lambda: the DIY agent loop (Bedrock Converse tool-use -> Athena) ----
    // The function timeout matches the API Gateway integration timeout. The handler stops
    // polling Athena and starting new model turns after RESPONSE_DEADLINE_SECONDS, which
    // leaves time for the final model call that summarizes the rows.
    const apiHandler = new lambda.Function(this, 'ApiHandler', {
      runtime: PYTHON_RUNTIME,
      architecture: PYTHON_ARCHITECTURE,
      handler: 'api_handler.handler',
      code: pythonCode(path.join(__dirname, '..', 'lambda', 'api-handler')),
      role: logRole,
      logGroup: apiHandlerLogs,
      timeout: cdk.Duration.seconds(API_INTEGRATION_TIMEOUT_SECONDS),
      memorySize: 512,
      environment: {
        MODEL_ID: props.modelId,
        ATHENA_WORKGROUP: props.workgroupName,
        GLUE_CATALOG_NAME: props.glueCatalogName,
        GLUE_DATABASE: props.glueDatabase,
        MAX_TOOL_TURNS: '6',
        RESPONSE_DEADLINE_SECONDS: '22',
        ...(props.modelTemperature === undefined ? {} : { MODEL_TEMPERATURE: String(props.modelTemperature) }),
      },
    });

    // ---- authorizer Lambda: OIDC issuer/audience + required group claim ----
    const authorizerFn = new lambda.Function(this, 'LogAgentAuthorizer', {
      runtime: PYTHON_RUNTIME,
      architecture: PYTHON_ARCHITECTURE,
      handler: 'authorizer.handler',
      code: pythonCode(path.join(__dirname, '..', 'lambda', 'authorizer')),
      logGroup: authorizerLogs,
      timeout: cdk.Duration.seconds(10),
      environment: {
        OIDC_ISSUER: props.oidcIssuer,
        OIDC_AUDIENCE: props.oidcAudience,
        REQUIRED_GROUP: props.requiredGroup,
      },
    });

    // ---- Private regional REST API Gateway ----
    // Private REST APIs REQUIRE a resource policy. Callers present an OIDC bearer token
    // rather than SigV4 credentials, so principal-based keys such as aws:PrincipalOrgID are
    // absent from the request and cannot gate access. The network boundary is the VPC
    // endpoint instead: the explicit Deny is evaluated before the Lambda authorizer runs,
    // so a request from any other endpoint is refused without reaching it.
    const fromApiEndpoint = { 'aws:SourceVpce': props.apiResourcePolicySourceVpce };
    const resourcePolicy = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.DENY,
          principals: [new iam.AnyPrincipal()],
          actions: ['execute-api:Invoke'],
          resources: ['execute-api:/*'],
          conditions: { StringNotEquals: fromApiEndpoint },
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          principals: [new iam.AnyPrincipal()],
          actions: ['execute-api:Invoke'],
          resources: ['execute-api:/*'],
          conditions: { StringEquals: fromApiEndpoint },
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
    new cdk.CfnOutput(this, 'ApiHandlerFunctionName', { value: apiHandler.functionName });
    new cdk.CfnOutput(this, 'ApiHandlerLogGroupName', { value: apiHandlerLogs.logGroupName });
    new cdk.CfnOutput(this, 'AthenaResultsBucketName', { value: resultsBucket.bucketName });

    // Keep the data catalog dependency explicit so the workgroup/role resolve names it registers.
    dataCatalog.node.addDependency(workgroup);
  }
}
