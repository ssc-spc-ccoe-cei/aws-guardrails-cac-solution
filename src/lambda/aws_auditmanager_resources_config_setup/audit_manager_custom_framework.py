# This file maps the GC Lambdas to audit manager control sets.
# When a new lambda is added or a lambda name is changed, this file needs to be updated.

frameworks_data = [
    {
        "name": "GC Cloud Guardrails Framework",
        "type": "Custom",
        "complianceType": "GC Cloud Guardrails",
        "description": "GC Cloud Operationalization Framework - GC Cloud Guardrails (https://github.com/canada-ca/cloud-guardrails)",
        "controlSources": "AWS Config",
        "controlSets": [
            {
                "name": "01-Protect User Accounts And Identities",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc01_check_alerts_flag_misuse",
                        "description": "Confirm that alerts to the authorized personnel have been implemented to flag misuse or suspicious activities for all user accounts.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/01_Protect-user-accounts-and-identities.md",
                        "testingInformation": "Validates that either GuardDuty is enabled and rules are set to report GuardDuty findings or AWS Event Rules are setup to report suspicious activity to an authorized personnel.",
                        "actionPlanTitle": "Setup Alerts To Flag Misuse",
                        "actionPlanInstructions": "Ensure either GuardDuty is enabled and rules are set to report GuardDuty findings or AWS Event Rules are setup to report suspicious activity to an authorized personnel.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "AlertsFlagMisuse-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc01_check_alerts_flag_misuse-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc01_check_attestation_letter",
                        "description": "Confirm that an attestation letter of the emergency break glass procedure has been provided by the Departmental CIO and CSO. Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/01_Protect-user-accounts-and-identities.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Provide an Attestation Letter of the Emergency Break Glass Procedure",
                        "actionPlanInstructions": "Ensure an emergency break glass procedure has been developed and attested by the Departmental CIO and CSO.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "S3-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc01_check_attestation_letter-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc01_check_dedicated_admin_account",
                        "description": "Provides evidence that there are dedicated user accounts for administration.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/01_Protect-user-accounts-and-identities.md",
                        "testingInformation": "Checks that there is at least 1 privileged IAM or SSO identity store user with administrator access to an account and that there are no non-privileged IAM or SSO identity store users with administrator acess.",
                        "actionPlanTitle": "Add Or Remove Permissions From Users",
                        "actionPlanInstructions": "Using AWS IAM or Identity Center, add/remove the required permissions from privileged and non-privileged users.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "DedicatedAdminAccount-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc01_check_dedicated_admin_account-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc01_check_federated_users_mfa",
                        "description": "Confirm that MFA is implemented according to GC guidance through screenshots, compliance reports, or compliance checks enabled through a reporting tool for federated users.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/01_Protect-user-accounts-and-identities.md",
                        "testingInformation": "Validates that MFA has been enabled for federated users.",
                        "actionPlanTitle": "Enable MFA for Federated Users",
                        "actionPlanInstructions": "Ensure MFA is enabled on the federated user's identity provider.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "FederatedUsersMFA-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc01_check_federated_users_mfa-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc01_check_iam_users_mfa",
                        "description": "Confirm that MFA is implemented according to GC guidance through screenshots, compliance reports, or compliance checks enabled through a reporting tool for IAM users.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/01_Protect-user-accounts-and-identities.md",
                        "testingInformation": "Validates that MFA has been enabled for all IAM users.",
                        "actionPlanTitle": "Enable MFA for IAM users",
                        "actionPlanInstructions": "Follow the instructions provided at https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "IAMUsersMFA-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc01_check_iam_users_mfa-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc01_check_mfa_digital_policy",
                        "description": "Confirm that digital policies are in place to ensure that MFA configurations are enforced.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/01_Protect-user-accounts-and-identities.md",
                        "testingInformation": "Validates that digital policies are in place. Because AWS does not support having policies to enforce MFA this check doesn't apply to root or iam users.",
                        "actionPlanTitle": "Create a Digital Policy To Ensure MFA",
                        "actionPlanInstructions": "Ensure a digital policy is put in place with your federated user's identity provider.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "MFADigitalPolicy-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc01_check_mfa_digital_policy-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc01_check_monitoring_and_logging",
                        "description": "Confirm whether monitoring and auditing is implemented for all user accounts.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/01_Protect-user-accounts-and-identities.md",
                        "testingInformation": "Validates that CloudTrails is enabled for your account and that monitoring is enabled.",
                        "actionPlanTitle": "Setup a CloudTrail",
                        "actionPlanInstructions": "Follow the instructions provided to setup a CloudTrail https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-trails.html",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "MonitoringAndLogging-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc01_check_monitoring_and_logging-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc01_check_root_mfa",
                        "description": "Ensure multi-factor authentication (MFA) mechanism is implemented for root account.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/01_Protect-user-accounts-and-identities.md",
                        "testingInformation": "Validates that MFA has been enabled for the root account.",
                        "actionPlanTitle": "Enable MFA for the Root Account",
                        "actionPlanInstructions": "Follow the instructions provided at https://docs.aws.amazon.com/accounts/latest/reference/root-user-mfa.html",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "RootMFA-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc01_check_root_mfa-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                ],
            },
            {
                "name": "02-Manage Access",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc02_check_access_management_attestation",
                        "description": "Confirm that the access authorization mechanisms have been implemented. Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/02_Manage-Access.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Confirm that the access authorization mechanisms have been implemented",
                        "actionPlanInstructions": "Upload the file to an S3 bucket and provide the path to the AWS Config control.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "IAMPrivilegedRolesReview-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc02_check_access_management_attestation-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc02_check_group_access_configuration",
                        "description": "Demonstrate access configurations and policies are implemented for different classes of users.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/02_Manage-Access.md",
                        "testingInformation": "Checks IAM and identity center groups to ensure that only admin groups have admin policies and members. And only non admin groups have non admin policies.",
                        "actionPlanTitle": "Review Group Access Configuration",
                        "actionPlanInstructions": "Go to AWS Identity and Access Management (IAM) and AWS Identity Center and review group policy document or permission set assignments, and group memberships.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "GroupAccessConfiguration-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc02_check_group_access_configuration-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc02_check_iam_password_policy",
                        "description": "Confirm password policy aligns with GC Password Guidance as appropriate.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/02_Manage-Access.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Review AWS IAM Password Policy",
                        "actionPlanInstructions": "Go to AWS Identity and Access Management (IAM), Account settings, and review the Password Policy to ensure minimum length is 12 characters, no complexity, and no password expiration.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "IAMPasswordPolicy-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc02_check_iam_password_policy-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc02_check_password_protection_mechanisms",
                        "description": "Confirm password policy aligns with GC Password Guidance as appropriate.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/02_Manage-Access.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Review AWS IAM Password Policy",
                        "actionPlanInstructions": "Go to AWS Identity and Access Management (IAM), Account settings, and review the Password Policy to ensure minimum length is 12 characters, no complexity, and no password expiration.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "IAMPasswordPolicy-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc02_check_password_protection_mechanisms-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc02_check_privileged_roles_review",
                        "description": "Verifies that a review of role assignment for root or global administrator accounts is performed at least every 12 months.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/02_Manage-Access.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Provide an Access Review Management document that meets GC requirements",
                        "actionPlanInstructions": "Upload the file to an S3 bucket and provide the path to the AWS Config control.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "IAMPrivilegedRolesReview-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc02_check_privileged_roles_review-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                ],
            },
            {
                "name": "03-Secure Endpoints",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc03_check_endpoint_access_config",
                        "description": "Demonstrate that access configuration and policies are implemented for devices.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/03_Secure-Endpoints.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Ensure Validation Is Compliant With Federated Idp",
                        "actionPlanInstructions": "Ensure that the Federated Idp is compliant with this guardrail validation.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "EndpointAccessConfig-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc03_check_endpoint_access_config-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc03_check_trusted_devices_admin_access",
                        "description": "Confirm ASEA CloudWatch Alarms are configured for access from Unauthorized IP addresses and sign-in without MFA..Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/03_Secure-Endpoints.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Review CloudWatch Alarms",
                        "actionPlanInstructions": "Go to AWS CloudWatch Alarms, and ensure alarms have been configured as required.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "CW-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc03_check_trusted_devices_admin_access-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                ],
            },
            {
                "name": "04-Enterprise Monitoring Accounts",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc04_check_alerts_flag_misuse",
                        "description": "Confirm that alerts to authorized personnel have been implemented to flag misuse, suspicious sign-in attempts, or when changes are made to privileged and non-privileged accounts.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/04_Enterprise-Monitoring-Accounts.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Create Event Bridge Rules To Flag Misuse",
                        "actionPlanInstructions": "Go into the AWS Event Bridge console and configure Rules to flag misuse, suspicious sign-in attemps, or when changes are made to the cloud broker role.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "Rules-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc04_check_alerts_flag_misuse-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc04_check_enterprise_monitoring",
                        "description": "Confirms that the AWS IAM Role and AWS IAM Policy exist and are attached.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/04_Enterprise-Monitoring-Accounts.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Create the AWS IAM Role and IAM Policy for Enterprise Monitoring",
                        "actionPlanInstructions": "Go into the AWS IAM console and configure the role and policy as required.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "IAM-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc04_check_enterprise_monitoring-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                ],
            },
            {
                "name": "05-Data Location",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc05_check_data_location",
                        "description": "Confirm if resources have been deployed to unauthorized regions. Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/05_Data-Location.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Review logs and deployments for unauthorized use of regions outside Canada",
                        "actionPlanInstructions": "Review existing deployments for resources outside of Canada. Lambda function logs provides more details on findings.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "Resource Check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc05_check_data_location-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    }
                ],
            },
            {
                "name": "06-Protection of Data-at-Rest",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc06_check_encryption_at_rest_part1",
                        "description": "Confirm policy for encryption (e.g. storage and/or VM based on risk-based assessment).Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/06_Protect-Data-at-Rest.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Ensure data at rest is protected",
                        "actionPlanInstructions": "Ensure data repositories are encrypted at rest",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "ResourceCheck",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc06_check_encryption_at_rest_part1-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc06_check_encryption_at_rest_part2",
                        "description": "Confirm policy for encryption (e.g. storage and/or VM based on risk-based assessment).Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/06_Protect-Data-at-Rest.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Ensure data at rest is protected",
                        "actionPlanInstructions": "Ensure data repositories are encrypted at rest",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "ResourceCheck",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc06_check_encryption_at_rest_part2-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                ],
            },
            {
                "name": "07-Protection of Data-in-Transit",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc07_check_certificate_authorities",
                        "description": "Confirm that non-person entity certificates are issued from certificate authorities that align with GC recommendations for TLS server certificates.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/07_Protect-Data-in-Transit.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Ensure Certificates Are Aligned With GC Recommendations",
                        "actionPlanInstructions": "Review all certificates in AWS Certificate Manager and ensure they are aligned with GC recommendations.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "CertificateAuthoritiesCheck",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc07_check_certificate_authorities-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc07_check_cryptographic_algorithms",
                        "description": "Confirm that cryptographic algorithms and protocols configurable by the user are in accordance with ITSP.40.111 and ITSP.40.062.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/07_Protect-Data-in-Transit.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Ensure Cryptographic Algorithms",
                        "actionPlanInstructions": "Review all Elastic Load Balancer Classic Loadbalancer's with a custom policy and ensure that the policies are using a protocol and cipher suite that meets GC recommendations.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "CryptographicAlgorithmsCheck",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc07_check_cryptographic_algorithms-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc07_check_encryption_in_transit",
                        "description": "Confirm policy for secure network transmission.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/07_Protect-Data-in-Transit.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Ensure endpoints leverage TLS",
                        "actionPlanInstructions": "Review all endpoint configuration to ensure Transport Layer Security (TLS) is leveraged for encryption in-transit.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "ResourceCheck",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc07_check_encryption_in_transit-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc07_check_secure_network_transmission_policy",
                        "description": "Confirm that a secure network transmission policy has been provided.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/07_Protect-Data-in-Transit.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Provide a Secure Network Transmission Policy document",
                        "actionPlanInstructions": "Ensure a policy for Secure Network Transmission has been developed.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "S3-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc07_check_secure_network_transmission_policy-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                ],
            },
            {
                "name": "08-Segment and Separate",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc08_check_cloud_deployment_guide",
                        "description": "Confirm that a Cloud Deployment Guide document has been provided.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/08_Segmentation.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Provide a Cloud Deployment Guide document that meets GC requirements",
                        "actionPlanInstructions": "Upload the file to an S3 bucket and provide the path to the AWS Config control.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "CloudDeploymentGuide-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc08_check_cloud_deployment_guide-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc08_check_cloud_segmentation_design",
                        "description": "Confirm that a Cloud Segmentation Design document has been provided.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/08_Segmentation.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Provide a Cloud Segmentation Design document that meets GC requirements",
                        "actionPlanInstructions": "Upload the file to an S3 bucket and provide the path to the AWS Config control.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "CloudSegmentationDesign-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc08_check_cloud_segmentation_design-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc08_check_target_network_architecture",
                        "description": "Confirm that a Target Network Architecture document has been provided.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/08_Segmentation.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Provide a Target Network Architecture document that meets GC requirements",
                        "actionPlanInstructions": "Upload the file to an S3 bucket and provide the path to the AWS Config control.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "TargetNetworkArchitectureDoc-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc08_check_target_network_architecture-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                ],
            },
            {
                "name": "09-Network Security Services",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc09_check_netsec_architecture",
                        "description": "Confirm that a Network Security Architecture document has been provided.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/09_Network-Security-Services.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Provide a Network Security Architecture document that meets GC requirements",
                        "actionPlanInstructions": "Upload the file to an S3 bucket and provide the path to the AWS Config control.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "S3-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc09_check_netsec_architecture-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc09_check_non_public_storage_accounts",
                        "description": "Confirm storage accounts are not exposed to the public.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/09_Network-Security-Services.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Configure Buckets To Deny Public Access",
                        "actionPlanInstructions": "Ensure that all S3 bucket Public Access Blocks are configured to deny public access.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "NonPublicStorageAccounts-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc09_check_non_public_storage_accounts-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                ],
            },
            {
                "name": "10-Cyber Defense Services",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc10_check_cyber_center_sensors",
                        "description": "Confirm that Cyber Center's sensors or other cyber defence services are implemented where available.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/10_Cyber-Defense-Services.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Setup Cyber Center Sensors",
                        "actionPlanInstructions": "Ensure that the cbs-global-reader role exists and a Log Archive account exists with S3 buckets that have a replication policy which replicates log data to Cyber Center.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "CyberCenterSensors-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc10_check_cyber_center_sensors-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                ],
            },
            {
                "name": "11-Logging and Monitoring",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc11_check_monitoring_all_users",
                        "description": "Confirms whether monitoring and auditing is implemented for all users.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/11_Logging-and-Monitoring.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Setup a CloudTrail",
                        "actionPlanInstructions": "Follow the instructions provided to setup a CloudTrail https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-trails.html",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "MonitoringAllUsers-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc11_check_monitoring_all_users-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc11_check_monitoring_use_cases",
                        "description": "Demonstrates that the monitoring use cases for the cloud platform have been implemented and have been integrated with the overall security monitoring activities being performed by the department.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/11_Logging-and-Monitoring.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Provide a Monitoring Use Cases document that meets GC requirements",
                        "actionPlanInstructions": "Upload the file to an S3 bucket and provide the path to the AWS Config control.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "MonitoringUseCases-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc11_check_monitoring_use_cases-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc11_check_policy_event_logging",
                        "description": "Ensures AWS CloudTrail has been configured using best practices.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/11_Logging-and-Monitoring.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Review AWS CloudTrail",
                        "actionPlanInstructions": "Ensure AWS CloudTrail has been configured based on best practices, including S3 data access logging.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "AWS Config - CLOUDTRAIL_S3_DATAEVENTS_ENABLED",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "CLOUDTRAIL_S3_DATAEVENTS_ENABLED",
                                },
                            },
                            {
                                "sourceName": "AWS Config - CLOUDTRAIL_SECURITY_TRAIL_ENABLED",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "CLOUDTRAIL_SECURITY_TRAIL_ENABLED",
                                },
                            },
                            {
                                "sourceName": "AWS Config - CLOUD_TRAIL_ENABLED",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "CLOUD_TRAIL_ENABLED",
                                },
                            },
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc11_check_security_contact",
                        "description": "Confirm that valid alternate security contact has been configured for the account.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/11_Logging-and-Monitoring.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Ensure the AWS Account alternate contacts are registered",
                        "actionPlanInstructions": "Review the alternate contacts configuration and ensure a valid Security contact has been established.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "AWS Account - Alternate Contacts",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc11_check_security_contact-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc11_check_timezone",
                        "description": "Confirm that the appropriate timezone has been set.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/11_Logging-and-Monitoring.md",
                        "testingInformation": "",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "Timezone-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc11_check_timezone-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc11_check_trail_logging",
                        "description": "Confirms that AWS CloudTrail trails have been created and are actively logging.Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/11_Logging-and-Monitoring.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Ensure AWS CloudTrail has been properly configured",
                        "actionPlanInstructions": "Review the AWS CloudTrail trails configuration and ensure these are logging.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "AWS Account - CloudTrail Status",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc11_check_trail_logging-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                ],
            },
            {
                "name": "12-Configuration of Cloud Marketplaces",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc12_check_private_marketplace",
                        "description": "Confirm that third-party marketplace restrictions have been implemented. Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/12_Cloud-Marketplace-Config.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Ensure the AWS Organization has a Private Marketplace",
                        "actionPlanInstructions": "Follow the instructions available in the link below to configure a Private Marketplacehttps://docs.aws.amazon.com/marketplace/latest/buyerguide/private-marketplace.html",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "AWS Marketplace Catalog Check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc12_check_private_marketplace-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    }
                ],
            },
            {
                "name": "13-Plan for Continuity",
                "controls": [
                    {
                        "type": "Custom",
                        "name": "gc13_check_emergency_account_alerts",
                        "description": "Verify that alerts are in place to report any use of emergency accounts. Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/13_Plan-for-Continuity.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Setup Emergency Account Alerts",
                        "actionPlanInstructions": "Ensure that Event Bridge Rules are setup to report any use of emergency accounts to authorized personnel.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "EmergencyAccountAlerts-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc13_check_emergency_account_alerts-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc13_check_emergency_account_management",
                        "description": "Verifies that an emergency account management procedure has been developed. Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/13_Plan-for-Continuity.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Provide an Emergency Account Management Procedures document that meets GC requirements",
                        "actionPlanInstructions": "Upload the file to an S3 bucket and provide the path to the AWS Config control.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "EmergencyAccountManagement-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc13_check_emergency_account_management-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc13_check_emergency_account_mgmt_approvals",
                        "description": "Confirm through attestation that the departmental CIO, in collaboration with DOCS, has approved the emergency account management procedure for the cloud service. Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/13_Plan-for-Continuity.md",
                        "testingInformation": "",
                        "actionPlanTitle": "Provide an Emergency Account Management Approvals document that meets GC requirements",
                        "actionPlanInstructions": "Upload the file to an S3 bucket and provide the path to the AWS Config control.",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "EmergencyAccountManagementApprovals-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc13_check_emergency_account_mgmt_approvals-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                    {
                        "type": "Custom",
                        "name": "gc13_check_emergency_account_testing",
                        "description": "Verify that testing of emergency accounts took place, and that periodic testing is included in emergency account management procedures. Source: https://github.com/canada-ca/cloud-guardrails/blob/master/EN/12_Cloud-Marketplace-Config.md",
                        "testingInformation": "",
                        "controlSources": "AWS Config",
                        "controlMappingSources": [
                            {
                                "sourceName": "EmergencyAccountTesting-check",
                                "sourceSetUpOption": "System_Controls_Mapping",
                                "sourceType": "AWS_Config",
                                "sourceKeyword": {
                                    "keywordInputType": "SELECT_FROM_LIST",
                                    "keywordValue": "Custom_gc13_check_emergency_account_testing-conformance-pack",
                                },
                            }
                        ],
                        "tags": {},
                    },
                ],
            },
        ],
        "tags": {},
    }
]
