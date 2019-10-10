"""Code for building Graph objects for testing purposes"""

#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU Affero General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.

import sys

import principalmapper
from principalmapper.common import Graph, Node, Policy
from principalmapper.graphing.edge_identification import obtain_edges, checker_map


def build_empty_graph() -> Graph:
    """Constructs and returns a Graph object with no nodes, edges, policies, or groups"""
    return Graph([], [], [], [], _get_default_metadata())


def build_graph_with_one_admin() -> Graph:
    """Constructs and returns a Graph object with one node that is an admin"""
    admin_user_arn = 'arn:aws:iam::000000000000:user/admin'
    policy = Policy(admin_user_arn, 'InlineAdminPolicy', _get_admin_policy())
    node = Node(admin_user_arn, 'AIDA00000000000000000', [policy], [], None, None, 1, True, True)
    return Graph([node], [], [policy], [], _get_default_metadata())


# noinspection PyListCreation
def build_playground_graph() -> Graph:
    """Constructs and returns a Graph objects with many nodes, edges, groups, and policies"""
    common_iam_prefix = 'arn:aws:iam::000000000000:'

    # policies to use and add
    admin_policy = Policy('arn:aws:iam::aws:policy/AdministratorAccess', 'AdministratorAccess', _get_admin_policy())
    ec2_for_ssm_policy = Policy('arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM', 'AmazonEC2RoleforSSM',
                                _get_ec2_for_ssm_policy())
    s3_full_access_policy = Policy('arn:aws:iam::aws:policy/AmazonS3FullAccess', 'AmazonS3FullAccess',
                                   _get_s3_full_access_policy())
    jump_policy = Policy('arn:aws:iam::000000000000:policy/JumpPolicy', 'JumpPolicy', _get_jump_policy())
    policies = [admin_policy, ec2_for_ssm_policy, s3_full_access_policy, jump_policy]

    # IAM role trust docs to be used
    ec2_trusted_policy_doc = _make_trust_document({'Service': 'ec2.amazonaws.com'})
    root_trusted_policy_doc = _make_trust_document({'AWS': 'arn:aws:iam::000000000000:root'})
    alt_root_trusted_policy_doc = _make_trust_document({'AWS': '000000000000'})
    other_acct_trusted_policy_doc = _make_trust_document({'AWS': '999999999999'})

    # nodes to add
    nodes = []
    # Regular admin user
    nodes.append(Node(common_iam_prefix + 'user/admin', 'AIDA00000000000000000', [admin_policy], [], None, None, 1, True, True))

    # Regular ec2 role
    nodes.append(Node(common_iam_prefix + 'role/ec2_ssm_role', 'AIDA00000000000000001', [ec2_for_ssm_policy], [],
                      ec2_trusted_policy_doc, common_iam_prefix + 'instance-profile/ec2_ssm_role', 0, False, False))

    # ec2 role with admin
    nodes.append(Node(common_iam_prefix + 'role/ec2_admin_role', 'AIDA00000000000000002', [ec2_for_ssm_policy], [], ec2_trusted_policy_doc,
                      common_iam_prefix + 'instance-profile/ec2_admin_role', 0, False, True))

    # assumable role with s3 access
    nodes.append(Node(common_iam_prefix + 'role/s3_access_role', 'AIDA00000000000000003', [s3_full_access_policy], [], root_trusted_policy_doc,
                      None, 0, False, False))

    # second assumable role with s3 access with alternative trust policy
    nodes.append(Node(common_iam_prefix + 'role/s3_access_role_alt', 'AIDA00000000000000004', [s3_full_access_policy], [],
                 alt_root_trusted_policy_doc, None, 0, False, False))

    # externally assumable role with s3 access
    nodes.append(Node(common_iam_prefix + 'role/external_s3_access_role', 'AIDA00000000000000005', [s3_full_access_policy], [],
                      other_acct_trusted_policy_doc, None, 0, False, False))

    # jump user with access to sts:AssumeRole
    nodes.append(Node(common_iam_prefix + 'user/jumpuser', 'AIDA00000000000000006', [jump_policy], [], None, None, 1, True, False))

    # user with S3 access, path in user's ARN
    nodes.append(Node(common_iam_prefix + 'user/somepath/some_other_jumpuser', 'AIDA00000000000000007', [jump_policy],
                      [], None, None, 1, True, False))

    # role with S3 access, path in role's ARN
    nodes.append(Node(common_iam_prefix + 'role/somepath/somerole', 'AIDA00000000000000008', [s3_full_access_policy],
                      [], alt_root_trusted_policy_doc, None, 0, False, False))

    # edges to add
    edges = obtain_edges(None, checker_map.keys(), nodes, sys.stdout, True)

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


def _get_jump_policy() -> dict:
    """Constructs and returns a dictionary representing a policy allowing sts:AssumeRole for any role"""
    return {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Action': 'sts:AssumeRole',
            'Resource': '*'
        }]
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


def _build_user_with_policy(policy_dict, policy_name='single_user_policy', user_name='asdf', number='0') -> Node:
    """Helper function: builds an IAM User with a given input policy."""
    policy = Policy('arn:aws:iam::000000000000:policy/{}'.format(policy_name), policy_name, policy_dict)
    result = Node(
        'arn:aws:iam::000000000000:user/{}'.format(user_name),
        'AIDA0000000000000000{}'.format(number),
        [policy],
        [],
        None,
        None,
        1,
        True,
        False
    )
    return result
