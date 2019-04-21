"""Code for building Graph objects for testing purposes"""

import principalmapper
from principalmapper.common.edges import Edge
from principalmapper.common.graphs import Graph
from principalmapper.common.groups import Group
from principalmapper.common.nodes import Node
from principalmapper.common.policies import Policy


def build_empty_graph() -> Graph:
    """Constructs and returns a Graph object with no nodes, edges, policies, or groups"""
    return Graph([], [], [], [], _get_default_metadata())


def build_graph_with_one_admin() -> Graph:
    """Constructs and returns a Graph object with one node that is an admin"""
    admin_user_arn = 'arn:aws:iam::000000000000:user/admin'
    policy = Policy(admin_user_arn, 'InlineAdminPolicy', _get_admin_policy())
    node = Node(admin_user_arn, [policy], [], None, 1, True, True)
    return Graph([node], [], [policy], [], _get_default_metadata())


def build_playground_graph() -> Graph:
    """Constructs and returns a Graph objects with many nodes, edges, groups, and policies"""
    common_iam_prefix = 'arn:aws:iam::000000000000:'

    # policies to use and add
    admin_policy = Policy('arn:aws:iam::aws:policy/AdministratorAccess', 'AdministratorAccess', _get_admin_policy())
    ec2_for_ssm_policy = Policy('arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM', 'AmazonEC2RoleforSSM',
                                _get_ec2_for_ssm_policy())
    s3_full_access_policy = Policy('arn:aws:iam::aws:policy/AmazonS3FullAccess', 'AmazonS3FullAccess',
                                   _get_s3_full_access_policy())
    policies = [admin_policy, ec2_for_ssm_policy, s3_full_access_policy]

    # IAM role trust docs to be used
    ec2_trusted_policy_doc = _make_trust_document({'Service': 'ec2.amazonaws.com'})
    root_trusted_policy_doc = _make_trust_document({'AWS': 'arn:aws:iam::000000000000:root'})
    alt_root_trusted_policy_doc = _make_trust_document({'AWS': '000000000000'})
    other_acct_trusted_policy_doc = _make_trust_document({'AWS': '999999999999'})

    # nodes to add
    nodes = []
    # Regular admin user
    nodes.append(Node(common_iam_prefix + 'user/admin', [admin_policy], [], None, 1, True, True))

    # Regular ec2 role
    nodes.append(Node(common_iam_prefix + 'role/ec2_ssm_role', [ec2_for_ssm_policy], [], ec2_trusted_policy_doc,
                      0, False, False))

    # ec2 role with admin

    # assumable role with s3 access

    # externally assumable role with s3 access

    # edges to add
    edges = []

    return Graph(nodes, edges, policies, [], _get_default_metadata())


def _get_admin_policy() -> dict:
    """Constructs and returns a dictionary representing an admin policy"""
    return {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Action': '*',
                'Resource': '*'
            }
        ]
    }


def _get_ec2_for_ssm_policy() -> dict:
    """Constructs and returns a dictionary representing the IAM policy AmazonEC2RoleforSSM"""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ssm:DescribeAssociation",
                    "ssm:GetDeployablePatchSnapshotForInstance",
                    "ssm:GetDocument",
                    "ssm:DescribeDocument",
                    "ssm:GetManifest",
                    "ssm:GetParameters",
                    "ssm:ListAssociations",
                    "ssm:ListInstanceAssociations",
                    "ssm:PutInventory",
                    "ssm:PutComplianceItems",
                    "ssm:PutConfigurePackageResult",
                    "ssm:UpdateAssociationStatus",
                    "ssm:UpdateInstanceAssociationStatus",
                    "ssm:UpdateInstanceInformation"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ssmmessages:CreateControlChannel",
                    "ssmmessages:CreateDataChannel",
                    "ssmmessages:OpenControlChannel",
                    "ssmmessages:OpenDataChannel"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2messages:AcknowledgeMessage",
                    "ec2messages:DeleteMessage",
                    "ec2messages:FailMessage",
                    "ec2messages:GetEndpoint",
                    "ec2messages:GetMessages",
                    "ec2messages:SendReply"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:PutMetricData"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstanceStatus"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ds:CreateComputer",
                    "ds:DescribeDirectories"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:PutLogEvents"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:GetEncryptionConfiguration",
                    "s3:AbortMultipartUpload",
                    "s3:ListMultipartUploadParts",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads"
                ],
                "Resource": "*"
            }
        ]
    }


def _get_s3_full_access_policy() -> dict:
    """Constructs and returns a dictionary representing an IAM policy granting full access to S3"""
    return {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Action': 's3:*',
                'Resource': '*'
            }
        ]
    }


def _get_default_metadata() -> dict:
    """Constructs and returns a metadata dictionary to use across tests"""
    return {'account_id': '000000000000', 'pmapper_version': principalmapper.__version__}


def _make_trust_document(principal_element: dict) -> dict:
    """Constructs and returns a dictionary representing a trust document used by IAM roles"""
    return {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': principal_element,
                'Action': 'sts:AssumeRole'
            }
        ]
    }
