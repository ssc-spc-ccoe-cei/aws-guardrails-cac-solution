# aws-guardrails-cac-solution

# GC Guardrails

- For detailed breakdown by lambda function, refer to [notes.md](./doc/NOTES.md)
- For manual deployment steps, refer to [manual.md](./doc/MANUAL.md)
- For steps to extend the current solution, refer to [enhance.md](./doc/ENHANCE.md)

## Deployment Steps

## LZA Considerations
- Stacksets containing AWSA roles cannot be created in an LZA configured organization
- Roles should be deployed as part of the LZA Customizations
- An example of LZA Customizations config is included in ./arch/lza_extensions
  - replacements-config.yaml can only be used in LZA 1.5.x+
  - both the customizations-config.yaml and the ./customizations/GCGuardrailsRoles.yaml need to be placed into the root of the LZA config  
  - customizations-config.yaml
    - `OrganizationName` needs to match the value configured in config.yaml
    - `AccelRolePrefix` needs to match the value configured in config.yaml
    - `RolePrefix` needs to match the value configured in config.yaml
    - `EvidenceBucketName` needs to match the value configured in config.yaml
    - `organizationalUnits` need to match what is deployed in the environment and must include any nested OU's
- After inserting the customizations-config, running the LZA pipeline will result in roles being created in any account they do not exist in, ioncluding new accounts
- Templates deployed through customizations-config are deployed as cloudformation stacks and not stacksets, allowing for the creation of priveledged roles.

### Pre-Requitites

- Enable StackSets trusted access (Visit the Cloudformation/Stacksets console).
- Organizations must be enabled and LZA deployed.
- Audit account must be configured as administrator for the aws config service.
- Installation user must have admin access to the Main Organizational account.
- AWS SAM must be installed on your local machine and capable of processing a build. (This can be done by ProServ prior to delivering the package).
- There must be an Org-Wide config aggregator in place, if there is not, after the initial deployment, deploy the ./arch/templates/config-aggregator.yaml template to the Audit Account.

### Edit the config file

The config file contains the variables required for the installation of the gc-guardrails dashboard components. Certain variables need to be configured based on information obtained from the organization console of your AWS management account.
The config file is documented below with inline commments:

```yaml
# The prefix to use in naming the cloudformation stacks
StackName: "gc-guardrails-"
# Set the following variable to 1.00, this variable can be used to update lambda functions.
GitSourceVersion: "1.00"
# The AWS region you are deploying to
AWS_REGION: "ca-central-1"
# This can be left blank
PipelineBucket: ""
# This sould be a short descriptive name for the environment
EnvironmentName: "esdc-lza-demo"
Parameters:
# This should be a short name describing the ogranization, used in the future for aggragating 
  OrganizationName: "ESDC-LZA-Demo"
# This is obtained from the the Organization console
  OrganizationId: "o-71q12of6wn"
# This is obtained from the the Organization console
  RootOUID: "r-tn6h"
# The Account ID of the Audit account
  AuditAccountID: "343164472410"
# The OU containing the audit account
  SecurityOUID: "ou-tn6h-t3orw7gj"
  # Can be left default
  RolePrefix: "gc-"
# Role prefix used to create roles with permissions to access all aws resources, this is usually defined in an SCP.
  AccelRolePrefix: "AWSA-"
  AcceleratorRole: "OrganizationAccountAccessRole"
  DestBucketName: ""
  EvidenceBucketName: ""
  AWSConfigConformsBucketName: ""
  AdditionalAssessmentAdminRoleARN: ""
  ExecutionName: ""
  # For LZA deployments where roles are deployed as part of customizations
  DeployRoles: "false"
```

### Create a cloudshell-package

Run the following to create build the lambda functions and package the deployment:

```
make build-cloudshell-package
```

This command will output a cloudshell-package.zip

### Upload and unpack the package

- Open a cloudshell instance on the Main Ogranization account
- Select Actions -> Upload and upload the cloudshell_package.zip, if there is already a file named cloudshell-package.zip you will need to remove the existing file.
- From the shell execute ```unzip ./cloudshell_package.zip -d /tmp/gc-dash```

### Install the product

- In the cloudshell navigate to the ```/tmp/gc-dash/``` directory
- Execute ```./cloudshell-config.sh``` this will install pre-reqs for a cloudshell deployment.
- Execute ```make all``` this will create a s3 bucket and deploy all of the components to the Organization and the member accounts of the organization. You can monitor the deployment through the cloudformation console in the management account.
- The config.yaml file will be backed up to the s3 bucket created by the deployment. This can be used in the future to deploy / re-deploy the packages or components as needed.

# Attestation Documents

After the installation of the GC_Guardrails components a new s3 bucket will be created in the Audit account. This bucket will be named ```gc-evidence-hash```. Within this bucket will be several directories, to become compliant with gc rules documents will need to be placed in these folders. This is described below:

- gc-01
  - filename: attestation_letter.pdf
  - contents: attestation letter of the emergency break glass procedure that has been signed by the Departmental CIO and CSO.
- gc-02
  - filename: account_management_plan.pdf
  - contents: privileged account management plan and process documentation.
- gc-07
  - filename: secure_network_transmission.pdf
  - contents: policy for secure network transmission.
- gc-08
  - filename: target_network_architecture.pdf
  - contents: target network architecture diagram with appropriate segmentation between network zones.
- gc-09
  - filename: network_security_architecture.pdf
  - contents:
    - policy for network boundary protection.
    - policy for limiting number of public IPs.
    - policy for limiting to authorized source IP addresses (e.g. GC IP addresses).
- gc-10
  - filename: signed_mou.pdf
  - contents: Confirmation from CCCS that the MOU has been signed by the Department.


