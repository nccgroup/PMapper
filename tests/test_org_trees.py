"""Tests for OrganizationTree objects"""

#  Copyright (c) NCC Group and Erik Steringer 2021. This file is part of Principal Mapper.
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

import logging
import unittest

from principalmapper.common import OrganizationTree
from tests.build_test_graphs import *
from tests.build_test_graphs import _build_user_with_policy
from principalmapper.common.nodes import Node
from principalmapper.common.policies import Policy
from principalmapper.querying.query_interface import local_check_authorization_full

logger = logging.getLogger(__name__)


class OrgTreeTests(unittest.TestCase):
    def test_admin_cannot_bypass_scps(self):
        graph = build_graph_with_one_admin()
        principal = graph.nodes[0]

        # SCP list of lists, this would be akin to an account in the root OU with the S3 service denied
        scp_collection = [
            [
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*"
                        }
                    ]
                }
            ],
            [
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*"
                        }
                    ]
                },
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": [
                                "s3:*"
                            ],
                            "Resource": "*",
                            "Sid": "Statement1"
                        }
                    ]
                }
            ]
        ]
        self.assertFalse(
            local_check_authorization_full(
                principal,
                's3:CreateBucket',
                'arn:aws:s3:::fakebucket',
                {},
                None,
                None,
                scp_collection,
                None
            )
        )
        self.assertTrue(
            local_check_authorization_full(
                principal,
                'ec2:RunInstances',
                '*',
                {},
                None,
                None,
                scp_collection,
                None
            )
        )

    def test_service_linked_role_avoids_scp_restriction(self):
        principal = Node(
            'arn:aws:iam::000000000000:role/AWSServiceRoleForSupport',
            'AROAASDF',
            [
                Policy(
                    'arn:aws:iam::000000000000:role/AWSServiceRoleForS3Support',
                    'inline-1',
                    {
                        'Version': '2012-10-17',
                        'Statement': [
                            {
                                'Effect': 'Allow',
                                'Action': 's3:*',
                                'Resource': '*'
                            }
                        ]
                    }
                )
            ],
            None,
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': 'sts:AssumeRole',
                        'Principal': {
                            'Service': 's3support.amazonaws.com'
                        }
                    }
                ]
            },
            None,
            0,
            False,
            False,
            None,
            False,
            None
        )
        # SCP list of lists, this would be akin to an account in the root OU with the S3 service denied
        scp_collection = [
            [
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*"
                        }
                    ]
                }
            ],
            [
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*"
                        }
                    ]
                },
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": [
                                "s3:*"
                            ],
                            "Resource": "*",
                            "Sid": "Statement1"
                        }
                    ]
                }
            ]
        ]
        self.assertTrue(
            local_check_authorization_full(
                principal,
                's3:CreateBucket',
                'arn:aws:s3:::fakebucket',
                {},
                None,
                None,
                scp_collection,
                None
            ),
            'AWSServiceRoleFor... check failed, this role should have access DESPITE the SCPs'
        )
        self.assertFalse(
            local_check_authorization_full(
                principal,
                'ec2:RunInstances',
                '*',
                {},
                None,
                None,
                scp_collection,
                None
            )
        )
