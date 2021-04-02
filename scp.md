Regional Control - attach to organization root
Except of the services included in NotAction block, all other services are denied if the requested regions are ‘us-east-1’ or ‘us-west-2’. NOTE: ‘Allow’ statement can’t have Condition - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_strategies.html#orgs_policies_allowlist 

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ServicesInApprovedRegions",
            "Effect": "Deny",
            "NotAction": [
                "iam:*",
                "organizations:*",
                "route53:*",
                "budgets:*",
                "waf:*",
                "cloudfront:*",
                "globalaccelerator:*",
                "importexport:*",
                "support:*",
                "sts:*",
                "config:*",
                "guardduty:*",
                "trustedadvisor:*",
                "ec2:DescribeInstances"
            ],
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {
                    "aws:RequestedRegion": [
                        "us-east-1",
                        "us-west-2"
                    ]
                },
                "ArnNotLike": {
                    "aws:PrincipalARN": [
                        "arn:aws:iam::*:role/aws-controltower-AdministratorExecutionRole",
                        "arn:aws:iam::*:role/aws-controltower-CloudWatchLogsRole",
                        "arn:aws:iam::*:role/aws-controltower-ConfigRecorderRole",
                        "arn:aws:iam::*:role/aws-controltower-ForwardSnsNotificationRole",
                        "arn:aws:iam::*:role/aws-controltower-ReadOnlyExecutionRole",
                        "arn:aws:iam::*:role/AWSControlTowerExecution",
                        "arn:aws:iam::*:role/aws-ct-tfextn-execution",
                        "arn:aws:iam::*:user/plcssops",
                        "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_AWSAdministratorAccess_*"
                    ]
                }
            }
        }
    ]
}
Approved list of AWS Services - attached to different OUs
Make use of allow and deny list strategy to allow/deny PL approved AWS services. More details: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_inheritance_auth.html 

For root - attach AWSFullAccess policy to allow all AWS services
Sandbox OU - explicitly deny AWS services that could create privileged resources
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyServices",
            "Effect": "Deny",
            "Action": [
                "ds:*",
            ],
            "Resource": [
                "*"
            ]
        },
       {
            "Sid": "DenyPublicACL",
            "Effect": "Deny",
            "Action": [
                "s3:PutBucketAcl",
                "s3:PutObjectAcl",
                "s3:PutObjectVersionAcl",
                "s3:CreateBucket"
             ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": [
                        "public-read",
                        "public-read-write",
                        "authenticated-read"
                    ]
            }
        } 
    ]
}
Prod OU - allow only PL approved AWS services by using combination of Deny and NotAction. e.g., below policy would deny all other services except the services included in the NotAction block
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowedServices",
            "Effect": "Deny",
            "NotAction": [
                "ec2:*",
                "lambda:*",
                "rds:*",
                "s3:*",
                "cloudfront:*",
                "sns:*",
                "glacier:*",
                "access-analyzer:*",
                "autoscaling-plans:*",
                "acm:*",
                "directconnect:*",
                "autoscaling:*"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
Protecting Shared Resources - attached to organization root
Control Tower Resources Protection
Addressed through mandatory guardrails available in AWS Control Tower service. Control Tower resources protected are:

Disallow changing data-at-rest encryption of Amazon S3 buckets in the log archive account
Disallow changing access logging for buckets in log archive account
Disallow changes to CloudWatch logs log groups
Disallow deletion of AWS Config aggregation authorization
Disallow deletion of log archive
Disallow policy changes to log archive
Disallow changing retention policy for log archive
Disallow configuration changes to CloudTrail
Disallow changing CloudTrail events being sent to CloudWatch Logs log files
Disallow removing CloudTrail in available regions
Disallow changing integrity validation for CloudTrail log file
Disallow changes to CloudWatch set up by AWS Control Tower
Disallow changes to AWS Config aggregation set up by AWS Control Tower
Disallow configuration changes to AWS Config
Disallow changes to AWS Config rules, Lambda functions and Amazon SNS notification/subscriptions settings, set up by AWS Control Tower
Deny leaving Organization
{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Deny",
        "Action": "organizations:LeaveOrganization",
        "Resource": "*"
    }
}
Restrict actions by root user
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootAccount",
      "Effect": "Deny",
      "NotAction": [
                "iam:*",
                "organizations:*",
                "sso:*"
      ],
      "Resource": "*",
      "Condition": {
         "StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}
      }
    },
    {
        "Sid": "GuardRootKeys",
        "Effect": "Deny",
        "Action": "iam:CreateAccessKey",
        "Resource": "arn:aws:iam::*:root"
    },
  ]
}
Protect GuardDuty, Security Hub
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "access-analyzer:DeleteAnalyzer",
        "ec2:DisableEbsEncryptionByDefault",
        "guardduty:AcceptInvitation",
        "guardduty:ArchiveFindings",
        "guardduty:CreateDetector",
        "guardduty:CreateFilter",
        "guardduty:CreateIPSet",
        "guardduty:CreateMembers",
        "guardduty:CreatePublishingDestination",
        "guardduty:CreateSampleFindings",
        "guardduty:CreateThreatIntelSet",
        "guardduty:DeclineInvitations",
        "guardduty:DeleteDetector",
        "guardduty:DeleteFilter",
        "guardduty:DeleteInvitations",
        "guardduty:DeleteIPSet",
        "guardduty:DeleteMembers",
        "guardduty:DeletePublishingDestination",
        "guardduty:DeleteThreatIntelSet",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:DisassociateMembers",
        "guardduty:InviteMembers",
        "guardduty:StartMonitoringMembers",
        "guardduty:StopMonitoringMembers",
        "guardduty:TagResource",
        "guardduty:UnarchiveFindings",
        "guardduty:UntagResource",
        "guardduty:UpdateDetector",
        "guardduty:UpdateFilter",
        "guardduty:UpdateFindingsFeedback",
        "guardduty:UpdateIPSet",
        "guardduty:UpdatePublishingDestination",
        "guardduty:UpdateThreatIntelSet",
        "securityhub:DeleteInvitations",
        "securityhub:DisableSecurityHub",
        "securityhub:DisassociateFromMasterAccount",
        "securityhub:DeleteMembers",
        "securityhub:DisassociateMembers"
      ],
      "Resource": "*"
    },
    "Condition": {
        "StringNotLike": {
          "aws:PrincipalARN":"arn:aws:iam::*:role/<name-of-admin-role-to-allow>"
        }
    }
  ]
}
Network security - Protect VPC flow logs, Internet GW
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ec2:DeleteFlowLogs",
        "logs:DeleteLogGroup",
        "logs:DeleteLogStream",
        "ec2:AttachInternetGateway",
        "ec2:CreateInternetGateway",
        "ec2:CreateEgressOnlyInternetGateway",
        "ec2:CreateVpcPeeringConnection",
        "ec2:AcceptVpcPeeringConnection",
        "globalaccelerator:Create*",
        "globalaccelerator:Update*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": [
         "ec2:DeleteTag",
         "ec2:CreateTag"
      ],
      "Resource": [
        "arn:aws:ec2:*:*:subnet/*",
        "arn:aws:ec2:*:*:network-acl/*",
        "arn:aws:ec2:*:*:transit-gateway-route-table/*"
      ],
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalARN":"arn:aws:iam::*:role/<name-of-admin-role-to-allow>"
        }
    }
  ]
 }
Use Instance Metadata v2
This policy will require role credentials for an EC2 to have been retrieved using the IMDSv2. Also, EC2s can only be created if IMDSv2 is used. Existing EC2s will not be impacted.

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "RequireAllEc2RolesToUseV2",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "NumericLessThan": {
                    "ec2:RoleDelivery": "2.0"
                }
            }
        },
        {
            "Sid": "RequireImdsV2",
            "Effect": "Deny",
            "Action": "ec2:RunInstances",
            "Resource": "arn:aws:ec2:*:*:instance/*",
            "Condition": {
                "StringNotEquals": {
                    "ec2:MetadataHttpTokens": "required"
                }
            }
         },
         {
            "Effect": "Deny",
            "Action": "ec2:ModifyInstanceMetadataOptions",
            "Resource": "*"
         },
         {
            "Sid": "MaxImdsHopLimit",
            "Effect": "Deny",
            "Action": "ec2:RunInstances",
            "Resource": "arn:aws:ec2:*:*:instance/*",
            "Condition": {
                "NumericGreaterThan": {"ec2:MetadataHttpPutResponseHopLimit": "1"}
            }
        }
    ]
}
Governance - attached to organization root
Require a tag on specified created resources
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCreateSecretWithNoCostCenterTag",
      "Effect": "Deny",
      "Action": "secretsmanager:CreateSecret",
      "Resource": "*",
      "Condition": {
         "Null": {
            "aws:RequestTag/CostCenter": "true"
        }
      }
    },
    {
      "Sid": "DenyRunInstanceWithNoCostCenterTag",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": [
        "arn:aws:ec2:*:*:instance/*",
        "arn:aws:ec2:*:*:volume/*"
      ],
      "Condition": {
         "Null": {
             "aws:RequestTag/CostCenter": "true"
        }
      }
    }
  ]
}
IAM Privileged Actions
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAccessWithException",
      "Effect": "Deny",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:DeleteRole",
        "iam:DeleteRolePermissionsBoundary",
        "iam:DeleteRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePermissionsBoundary",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:UpdateRole",
        "iam:UpdateRoleDescription"
      ],
      "Resource": [
        "arn:aws:iam::*:role/name-of-role-to-deny"
      ],
      "Condition": {
          "StringNotLike": {
              "aws:PrincipalARN":"arn:aws:iam::*:role/<name-of-admin-role-to-allow>"
        }
      }
    }
  ]
}
Protect Security Settings
{    
  "Version": "2012-10-17",
  "Statement": [
    {
        "Sid": "GuardGlacierDeletion",
        "Effect": "Deny",
        "Action": [
            "glacier:DeleteArchive",
            "glacier:DeleteVault"
        ],
        "Resource": "arn:aws:glacier:*:*:vaults/*"
   },
   {
        "Sid": "ProtectKMSKeys",
        "Action":[
            "kms:ScheduleKeyDeletion",
            "kms:Delete*"
         ],
         "Resource":"*",
         "Effect":"Deny",
         "Condition": {
                "ArnNotLike": {
                    "aws:PrincipalARN": [
                        "arn:aws:iam::*:role/AWSCloudFormationStackSetExecutionRole"
                    ]
                }
         }
    }
  ]
}
Requires all S3 bucket use AES256 or KMS encryption & protect changes to block public bucket setting
{
      "Version":"2012-10-17",
      "Statement":[
       {
         "Action": "s3:PutObject",
         "Resource":"*",
         "Effect":"Deny",
         "Condition":{
             "StringNotEquals":{
                  "s3:x-amz-server-side-encryption":["AES256","aws:kms"]}
                  }
        },
        {
          "Action":"s3:PutObject",
          "Resource":"*",
          "Effect":"Deny",
          "Condition":{
              "Bool":{"s3:x-amz-server-side-encryption":false}
            }
        },
       {
          "Action": [
              "s3:PutBucketPublicAccessBlock",
              "s3:DeletePublicAccessBlock",
              "s3:PutAccountPublicAccessBlock"
          ],
          "Resource":"*",
          "Effect":"Deny",
          "Condition":{
             "ArnNotLike": {
                    "aws:PrincipalARN": [<sanctioned-admin-roles>]
            }
        }
    ]
}
Additional SCPs for consideration:

Disallow modify account billing/payment methods
