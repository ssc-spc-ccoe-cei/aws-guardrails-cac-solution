
# Manual Deployment Steps

## Deployment with Makefile

Deploy the main stack via ```make``` command as follows:

```sh
# 1. NEW CLEAN DEPLOYMENT -- SETUP S3, BUILD, PACKAGE, AND DEPLOY THE MAIN STACK
make all

# 2. REDEPLOYMENT -- BUILD, PACKAGE, AND REDEPLOY THE MAIN STACK
make deploy

# 3. CFN TEMPLATES LINTING
make lint

# 4. STACK REMOVAL
make destroy
```

To redeploy specific StackSets (note: GC Guardrails are deployed as part of the Conformance Pack in StackSets, multi-account) after making function changes, run the following commands:

```sh
# BUILD, PACKAGE, AND REDEPLOY CHILD STACKSETS (1-8)

# SS1 RULES = GC02CheckAccountManagementPlan
make update-ss1

# S2 RULES = GC02CheckIAMUsersMFAL, GC02CheckIAMPasswordPolicy
make update-ss2

# SS3 RULES = GC07CheckSecureNetworkTransmissionPolicy, GC08CheckTargetNetworkArchitecture, GC09CheckNetworkSecurityArchitectureDocument, GC10CheckSignedMOU, GC11CheckSecurityContactLambda
make update-ss3

# SS4 RULES = GC11CheckTrailLogging, GC12CheckMarketplaces, GC01CheckRootAccountMFAEnabled, GC03CheckIAMCloudWatchAlarms
make update-ss4

# SS5 RULES = GC04CheckEnterpriseMonitoring, GC05CheckDataLocation
make update-ss5

# SS6 RULES = GC07CheckEncryptionInTransit
make update-ss6

# SS7 RULES = GC06CheckEncryptionAtRestPart1
make update-ss7

# SS8 RULES = GC06CheckEncryptionAtRestPart2
make update-ss8
```

## Manual Deployment

### 1.0 Environment Setup

```sh
# set global variables
export CODEBUILD_SRC_DIR=`pwd`
export AWS_REGION=ca-central-1
export PIPELINE_BUCKET=gc-guardrails-deployments-`aws sts get-caller-identity --query Account --output text`

# create s3 bucket
aws s3 mb s3://$PIPELINE_BUCKET
```

Once the pipeline bucket is created, apply the below bucket policy to grant S3 ```read``` access from other OU's (StackSets executions).

Replace ```{PIPELINE_BUCKET}``` and ```{ORGANIZATION_ID}``` with your IDs.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowOrganizationToReadPipelineBucket",
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::{PIPELINE_BUCKET}",
                "arn:aws:s3:::{PIPELINE_BUCKET}/*"
            ],
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalOrgID": "{ORGANIZATION_ID}"
                }
            }
        }
    ]
}
```


## 2.1 Code Packaging & Stack Deployment (obsolete, see README and makefile)

```sh
# set global variables
export STACK_NAME=gc-guardrails
export ENV_NAME=isengard-dev
export GIT_SOURCE_VERSION=1.00

# package lambdas & upload child templates to s3
$CODEBUILD_SRC_DIR/tools/package.sh -b $PIPELINE_BUCKET -r $AWS_REGION -t $CODEBUILD_SRC_DIR/arch/templates -p $CODEBUILD_SRC_DIR/arch/templates/build -g $GIT_SOURCE_VERSION

# deploy the main stack
aws cloudformation deploy --template-file ./arch/templates/build/main.yaml --stack-name "$STACK_NAME-$ENV_NAME" --parameter-overrides file://arch/params/${ENV_NAME}.json --s3-bucket $PIPELINE_BUCKET --capabilities CAPABILITY_NAMED_IAM
```

## 2.2 YAML Template Linting

```sh
# scan .yaml with cfn-lint & cfn-nag
$CODEBUILD_SRC_DIR/tools/cfnlint.sh
```

## 2.3 Updating Individual StackSets

```sh
# First ensure to repackage your template/ lambda code
# To list existing StackSets run the following
aws cloudformation list-stack-sets

# To update individual StackSet run the following
aws cloudformation update-stack-set --stack-set-name LCCFedGov-GC-AuditAccount-PreReqs-Part7 --template-body file://arch/templates/build/AuditAccountPreRequisitesPart7.yaml --parameters ParameterKey="AuditAccountID",UsePreviousValue=true ParameterKey="OrganizationName",UsePreviousValue=true ParameterKey="RolePrefix",UsePreviousValue=true
```

## 3. Working with SAM Services

### 3.1 Clean & Build

The script below will build all SAM Services in your solution. A SAM Service is currently identified by the presence of the `build.toml` file at the root of the SAM service:

```sh
# clean 'build' artifacts
${CODEBUILD_SRC_DIR}/tools/samclean.sh -p $CODEBUILD_SRC_DIR/src/lambda/

# rebuild lambdas
${CODEBUILD_SRC_DIR}/tools/buildsam.sh -p $CODEBUILD_SRC_DIR/src/lambda/
```
