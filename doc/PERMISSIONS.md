# Lambda Permissions
 
## Role Information
This page outlines the Lambda Execution Roles for the AWS CaC Solution, alongside the permissions assigned to each role. These permissions enable secure, read-oriented access to various AWS services. Each section describes the role's purpose, trust relationships, and the AWS actions it is authorized to perform.
 
### Name
`${AccelRolePrefix}GCLambdaExecutionRole2`

## Description
This role is designed to provide comprehensive read access across various AWS services, allowing for compliance and monitoring capabilities.
 
### TrustPrincipal
`arn:${AWS::Partition}:iam::${AuditAccountID}:root`
 
### SwitchRole
`${AcceleratorRole}`
 
## Policy Package
 
### Version
`2012-10-17`
 
### Statement
#### Effect
`Allow`
 
#### Sid
`GCComplianceAllowAccess2`
 
### Actions
The following actions are allowed across various AWS services:
 
- **ACM (AWS Certificate Manager)**: `Describe*`, `Get*`, `List*`
- **API Gateway**: `GET`
- **Backup**: `ListBackupVaults`, `ListRecoveryPointsByBackupVault`
- **Cassandra**: `Select`
- **CloudFront**: `Describe*`, `Get*`, `List*`
- **CloudTrail**: `DescribeTrails`, `Get*`, `ListTrails`, `LookupEvents`
- **CodeBuild**: `BatchGetProjects`, `ListProjects`
- **Config**: `PutEvaluations`
- **DocDB Elastic**: `List*`
- **DynamoDB**: `DescribeTable`, `ListTables`
- **EC2**: `Describe*`, `GetEbsEncryptionByDefault`
- **EKS**: `DescribeCluster`, `ListClusters`
- **ElastiCache**: `Describe*`
- **EFS (Elastic File System)**: `DescribeFileSystems`
- **ELB (Elastic Load Balancing)**: `Describe*`
- **Elasticsearch**: `DescribeElasticsearchDomains`, `ListDomainNames`
- **Kinesis**: `DescribeStream`, `ListStreams`
- **MemoryDB**: `Describe*`
- **Organizations**: `Describe*`, `List*`
- **QLDB (Quantum Ledger Database)**: `DescribeLedger`, `ListLedgers`
- **RDS (Relational Database Service)**: `Describe*`
- **Redshift**: `Describe*`
- **Resource Explorer 2**: `ListIndexes`, `Search`
- **S3 (Simple Storage Service)**: `Get*`, `List*`
- **SNS (Simple Notification Service)**: `GetTopicAttributes`, `ListTopics`
- **Tag**: `GetResources`
- **Timestream**: `DescribeEndpoints`, `List*`
 
### Resources
`*`
 

  
 
### Name
`${AccelRolePrefix}GCLambdaExecutionRole`

## Description
This role is designed to provide read access across various AWS services, allowing for compliance and monitoring capabilities. 
 
### TrustPrincipal
`arn:${AWS::Partition}:iam::${AuditAccountID}:root`
 
### SwitchRole
`${AcceleratorRole}`
 
## Policy Package
 
### Version
`2012-10-17`
 
### Statement
 
#### Effect
`Allow`
 
#### Sid
`GCComplianceAllowAccess`
 
### Actions
The following actions are allowed across various AWS services:
 
- **ACM (AWS Certificate Manager)**: `Describe*`, `Get*`, `List*`
- **API Gateway**: `GET`
- **AWS Marketplace**: `ListEntities`
- **Backup**: `List*`
- **Cassandra**: `Select`
- **CloudFront**: `Describe*`, `Get*`, `List*`
- **CloudTrail**: `DescribeTrails`, `Get*`, `ListTrails`, `LookupEvents`
- **CodeBuild**: `BatchGetProjects`, `ListProjects`
- **Config**: `PutEvaluations`
- **DAX (DynamoDB Accelerator)**: `DescribeClusters`
- **DocDB Elastic**: `ListClusters`, `ListClusterSnapshots`
- **DynamoDB**: `DescribeTable`, `ListTables`
- **EC2**: `Describe*`, `GetEbsEncryptionByDefault`
- **EKS**: `DescribeCluster`, `ListClusters`
- **ElastiCache**: `Describe*`
- **EFS (Elastic File System)**: `DescribeFileSystems`
- **IAM (Identity and Access Management)**: `GenerateCredentialReport`, `Get*`, `List*`, `Simulate*`
- **Kinesis**: `DescribeStream`, `ListStreams`
- **MemoryDB**: `Describe*`
- **Organizations**: `Describe*`, `List*`
- **QLDB (Quantum Ledger Database)**: `DescribeLedger`, `ListLedgers`
- **RDS (Relational Database Service)**: `Describe*`
- **Resource Explorer 2**: `ListIndexes`, `Search`
- **S3 (Simple Storage Service)**: `Get*`, `List*`
- **SNS (Simple Notification Service)**: `GetTopicAttributes`, `ListTopics`
- **Tag**: `GetResources`
- **Timestream**: `DescribeEndpoints`, `List*`
 
### Resources
`*`
 
#### Additional Statements
 
##### Bucket Access
- **Effect**: `Allow`
- **Sid**: `GcComplianceAllowBucketAccess`
- **Actions**: `s3:Get*`, `s3:ListBucket`
- **Resources**:
  - `arn:${AWS::Partition}:s3:::${AWSConfigConformsBucketName}`
  - `arn:${AWS::Partition}:s3:::${AWSConfigConformsBucketName}/*`
  - `arn:${AWS::Partition}:s3:::${ClientEvidenceBucket}`
  - `arn:${AWS::Partition}:s3:::${ClientEvidenceBucket}/*`
 
##### Account Info Access
- **Effect**: `Allow`
- **Sid**: `AllowReadAccountInfo`
- **Actions**: `account:GetAlternateContact`
- **Resources**:
  - `arn:aws:account::*:account`
  - `arn:aws:account::*:account/o-*/*`
 
##### List Bucket Access
- **Effect**: `Allow`
- **Sid**: `GcComplianceAllowListBucketAccess`
- **Actions**: `s3:ListAllMyBuckets`
- **Resources**: `*`
 


 
 
 
 