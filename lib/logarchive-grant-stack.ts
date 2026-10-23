import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as glue from 'aws-cdk-lib/aws-glue';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cr from 'aws-cdk-lib/custom-resources';

export interface LogArchiveGrantStackProps extends cdk.StackProps {
  /** AWS Organizations org id (e.g. o-xxxxxxxxxx); used in the CloudTrail S3 path. */
  readonly orgId: string;
  /** Account that runs the query agent and assumes the cross-account read role. */
  readonly queryAccount: string;
  /** Account this stack deploys into (the Log Archive account). */
  readonly logArchiveAccount: string;
  /** AWS region for the stack (also supplied via env; kept explicit for parity with LogQueryStackProps). */
  readonly region: string;
  /** Name of the cross-account read role in the query account. */
  readonly roleName: string;
  /** Glue database name for the central log catalog. */
  readonly glueDatabase: string;
  /** Override for the central log bucket name (defaults to the LZA convention). */
  readonly centralBucketName?: string;
}

/**
 * Deploys INTO the Log Archive account (Security OU). Grants the query
 * account's cross-account read role coarse read of the central logs, WITHOUT
 * Lake Formation (unavailable in some partitions such as GovCloud):
 *   - Glue Data Catalog database over the central log bucket
 *   - Glue catalog resource policy -> query role (GetDatabase/Table/Partitions)
 *
 * NOTE: the central log S3 bucket and its KMS CMK are landing-zone-managed. The
 * S3 bucket policy + KMS key grant to the query role must be added to the
 * landing-zone config (bucket-policies + the key policy), NOT owned here, to
 * avoid conflicting with the landing zone over the bucket. This stack prints the
 * exact statements to add (see outputs) and provisions the Glue pieces it does own.
 */
export class LogArchiveGrantStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: LogArchiveGrantStackProps) {
    super(scope, id, props);
    const queryAccount = props.queryAccount;
    const roleName = props.roleName;
    const dbName = props.glueDatabase;
    const orgId = props.orgId;
    const queryRoleArn = `arn:${this.partition}:iam::${queryAccount}:role/${roleName}`;
    // Landing-zone-managed central log bucket convention: aws-accelerator-central-logs-<acct>-<region>
    const centralBucket = props.centralBucketName ?? `aws-accelerator-central-logs-${this.account}-${this.region}`;

    // ---- Glue Data Catalog database over the central logs ----
    const db = new glue.CfnDatabase(this, 'CentralLogsDb', {
      catalogId: this.account,
      databaseInput: {
        name: dbName,
        description: 'Cross-account queryable catalog over the landing-zone central log bucket.',
        locationUri: `s3://${centralBucket}/`,
      },
    });

    // ---- CloudTrail table (org trail; CloudTrail SerDe; non-partitioned demo scan) ----
    // Production should add partition projection over year/month/day to bound scan cost.
    const cloudtrailTable = new glue.CfnTable(this, 'CloudTrailTable', {
      catalogId: this.account,
      databaseName: dbName,
      tableInput: {
        name: 'cloudtrail',
        description: 'Organization CloudTrail events (who did what).',
        tableType: 'EXTERNAL_TABLE',
        parameters: { classification: 'cloudtrail', EXTERNAL: 'TRUE' },
        storageDescriptor: {
          location: `s3://${centralBucket}/cloudtrail-organization/AWSLogs/${orgId}/`,
          inputFormat: 'com.amazon.emr.cloudtrail.CloudTrailInputFormat',
          outputFormat: 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
          serdeInfo: { serializationLibrary: 'com.amazon.emr.hive.serde.CloudTrailSerde' },
          columns: [
            { name: 'eventversion', type: 'string' },
            { name: 'useridentity', type: 'struct<type:string,principalid:string,arn:string,accountid:string,username:string,invokedby:string,accesskeyid:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>' },
            { name: 'eventtime', type: 'string' },
            { name: 'eventsource', type: 'string' },
            { name: 'eventname', type: 'string' },
            { name: 'awsregion', type: 'string' },
            { name: 'sourceipaddress', type: 'string' },
            { name: 'useragent', type: 'string' },
            { name: 'errorcode', type: 'string' },
            { name: 'errormessage', type: 'string' },
            { name: 'requestparameters', type: 'string' },
            { name: 'responseelements', type: 'string' },
            { name: 'additionaleventdata', type: 'string' },
            { name: 'requestid', type: 'string' },
            { name: 'eventid', type: 'string' },
            { name: 'eventtype', type: 'string' },
            { name: 'recipientaccountid', type: 'string' },
            { name: 'readonly', type: 'string' },
          ],
        },
      },
    });
    cloudtrailTable.addDependency(db);

    // ---- VPC flow logs table (default space-delimited format; non-partitioned) ----
    // Production should add partition projection over year/month/day to bound scan cost.
    const vpcFlowTable = new glue.CfnTable(this, 'VpcFlowLogsTable', {
      catalogId: this.account,
      databaseName: dbName,
      tableInput: {
        name: 'vpc_flow_logs',
        description: 'VPC flow logs (network connections).',
        tableType: 'EXTERNAL_TABLE',
        parameters: { classification: 'csv', EXTERNAL: 'TRUE', 'skip.header.line.count': '0' },
        storageDescriptor: {
          location: `s3://${centralBucket}/vpc-flow-logs/AWSLogs/`,
          inputFormat: 'org.apache.hadoop.mapred.TextInputFormat',
          outputFormat: 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
          serdeInfo: {
            serializationLibrary: 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe',
            parameters: { 'field.delim': ' ' },
          },
          columns: [
            { name: 'version', type: 'int' },
            { name: 'account_id', type: 'string' },
            { name: 'interface_id', type: 'string' },
            { name: 'srcaddr', type: 'string' },
            { name: 'dstaddr', type: 'string' },
            { name: 'srcport', type: 'int' },
            { name: 'dstport', type: 'int' },
            { name: 'protocol', type: 'bigint' },
            { name: 'packets', type: 'bigint' },
            { name: 'bytes', type: 'bigint' },
            { name: 'start', type: 'bigint' },
            { name: 'end', type: 'bigint' },
            { name: 'action', type: 'string' },
            { name: 'log_status', type: 'string' },
          ],
        },
      },
    });
    vpcFlowTable.addDependency(db);

    // ---- GuardDuty findings table (JSON SerDe; non-partitioned) ----
    // Production should add partition projection over year/month/day to bound scan cost.
    const guardDutyTable = new glue.CfnTable(this, 'GuardDutyTable', {
      catalogId: this.account,
      databaseName: dbName,
      tableInput: {
        name: 'guardduty',
        description: 'GuardDuty findings (threat detections).',
        tableType: 'EXTERNAL_TABLE',
        parameters: { classification: 'json', EXTERNAL: 'TRUE' },
        storageDescriptor: {
          location: `s3://${centralBucket}/guardduty/`,
          inputFormat: 'org.apache.hadoop.mapred.TextInputFormat',
          outputFormat: 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
          serdeInfo: { serializationLibrary: 'org.openx.data.jsonserde.JsonSerDe' },
          columns: [
            { name: 'id', type: 'string' },
            { name: 'type', type: 'string' },
            { name: 'severity', type: 'double' },
            { name: 'region', type: 'string' },
            { name: 'accountid', type: 'string' },
            { name: 'createdat', type: 'string' },
            { name: 'updatedat', type: 'string' },
            { name: 'title', type: 'string' },
            { name: 'description', type: 'string' },
            { name: 'resource', type: 'struct<resourcetype:string>' },
            { name: 'service', type: 'struct<action:struct<actiontype:string>>' },
          ],
        },
      },
    });
    guardDutyTable.addDependency(db);

    // ---- Network Firewall alert logs table (JSON SerDe; non-partitioned) ----
    // Production should add partition projection over year/month/day to bound scan cost.
    const networkFirewallTable = new glue.CfnTable(this, 'NetworkFirewallTable', {
      catalogId: this.account,
      databaseName: dbName,
      tableInput: {
        name: 'network_firewall',
        description: 'AWS Network Firewall alert/flow logs.',
        tableType: 'EXTERNAL_TABLE',
        parameters: { classification: 'json', EXTERNAL: 'TRUE' },
        storageDescriptor: {
          location: `s3://${centralBucket}/firewall/`,
          inputFormat: 'org.apache.hadoop.mapred.TextInputFormat',
          outputFormat: 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
          serdeInfo: { serializationLibrary: 'org.openx.data.jsonserde.JsonSerDe' },
          columns: [
            { name: 'event_timestamp', type: 'string' },
            { name: 'event_alert_action', type: 'string' },
            { name: 'event_alert_signature', type: 'string' },
            { name: 'event_src_ip', type: 'string' },
            { name: 'event_dest_ip', type: 'string' },
            { name: 'event_dest_port', type: 'int' },
            { name: 'event_proto', type: 'string' },
            { name: 'event_app_proto', type: 'string' },
            { name: 'event_tls_sni', type: 'string' },
          ],
        },
      },
    });
    networkFirewallTable.addDependency(db);

    // ---- Glue catalog resource policy: grant the query role read ----
    // (Glue resource policy is a PutResourcePolicy API call, not a CFN resource, so use
    //  a custom resource. One resource policy per account/region - merge if the LZA sets one.)
    const gluePolicyJson = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'SecurityLogAgentCatalogRead',
          Effect: 'Allow',
          Principal: { AWS: queryRoleArn },
          Action: ['glue:GetDatabase', 'glue:GetDatabases', 'glue:GetTable', 'glue:GetTables', 'glue:GetPartition', 'glue:GetPartitions'],
          Resource: [
            `arn:${this.partition}:glue:${this.region}:${this.account}:catalog`,
            `arn:${this.partition}:glue:${this.region}:${this.account}:database/${dbName}`,
            `arn:${this.partition}:glue:${this.region}:${this.account}:table/${dbName}/*`,
          ],
          Condition: { StringEquals: { 'aws:PrincipalOrgID': orgId } },
        },
      ],
    });
    const glueResourcePolicy = new cr.AwsCustomResource(this, 'GlueCatalogResourcePolicy', {
      onCreate: {
        service: 'Glue',
        action: 'putResourcePolicy',
        parameters: { PolicyInJson: gluePolicyJson, EnableHybrid: 'TRUE' },
        physicalResourceId: cr.PhysicalResourceId.of(`glue-resource-policy-${this.account}`),
      },
      onUpdate: {
        service: 'Glue',
        action: 'putResourcePolicy',
        parameters: { PolicyInJson: gluePolicyJson, EnableHybrid: 'TRUE' },
        physicalResourceId: cr.PhysicalResourceId.of(`glue-resource-policy-${this.account}`),
      },
      onDelete: { service: 'Glue', action: 'deleteResourcePolicy' },
      policy: cr.AwsCustomResourcePolicy.fromSdkCalls({ resources: cr.AwsCustomResourcePolicy.ANY_RESOURCE }),
    });
    glueResourcePolicy.node.addDependency(db);

    // ---- Statements to add to the landing-zone-managed central log bucket policy + KMS key ----
    const s3Statement = {
      Sid: 'SecurityLogAgentCrossAccountRead',
      Effect: 'Allow',
      Principal: { AWS: queryRoleArn },
      Action: ['s3:GetObject', 's3:ListBucket'],
      Resource: [
        `arn:${this.partition}:s3:::${centralBucket}`,
        `arn:${this.partition}:s3:::${centralBucket}/*`,
      ],
      Condition: { StringEquals: { 'aws:PrincipalOrgID': orgId } },
    };
    const kmsStatement = {
      Sid: 'SecurityLogAgentKmsDecrypt',
      Effect: 'Allow',
      Principal: { AWS: queryRoleArn },
      Action: ['kms:Decrypt', 'kms:DescribeKey'],
      Resource: '*',
      Condition: { StringEquals: { 'aws:PrincipalOrgID': orgId } },
    };

    new cdk.CfnOutput(this, 'GlueDatabase', { value: dbName });
    new cdk.CfnOutput(this, 'AddToCentralLogBucketPolicy', {
      description: 'Apply via the landing-zone config (central-log bucket policy), NOT attached directly here',
      value: JSON.stringify(s3Statement),
    });
    new cdk.CfnOutput(this, 'AddToCentralLogKmsKeyPolicy', {
      description: 'Apply via the landing-zone config (central-log KMS key policy), NOT attached directly here',
      value: JSON.stringify(kmsStatement),
    });
  }
}
