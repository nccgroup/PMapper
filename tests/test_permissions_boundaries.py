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

"""Test functions for permissions boundaries assigned to IAM Users/Roles."""

import logging
import unittest

from tests.build_test_graphs import *
from tests.build_test_graphs import _build_user_with_policy

from principalmapper.common import Policy
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.querying.query_interface import local_check_authorization, local_check_authorization_full


class LocalPermissionsBoundaryHandlingTests(unittest.TestCase):
    """Test cases to ensure that Principal Mapper correctly handles permission boundaries:

    https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
    """

    def test_permissions_boundary_no_resource_policy(self):
        """In the case of no resource policy, the effective permissions are the "intersection" of the caller's
        identity policies + the boundary policy. Both the user's identity policies + boundary policy must
        permit the API call. A matching deny statement in either set will deny the whole call.
        """
        boundary = Policy(
            'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess',
            'AmazonS3ReadOnlyAccess',
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": [
                            "s3:Get*",
                            "s3:List*"
                        ],
                        "Resource": "*",
                        "Effect": "Allow"
                    }
                ]
            }
        )

        iam_user_1 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }]
            },
            'admin_policy',
            'asdf1',
            '1'
        )

        iam_user_1.permissions_boundary = boundary

        self.assertTrue(
            local_check_authorization(iam_user_1, 's3:GetObject', 'arn:aws:s3:::bucket/object', {})
        )

        self.assertFalse(
            local_check_authorization(iam_user_1, 's3:PutObject', 'arn:aws:s3:::bucket/object', {})
        )

    def test_permissions_boundary_with_resource_policy(self):
        boundary_1 = Policy(
            'arn:aws:iam::aws:policy/AssumeJumpRole',
            'AssumeJumpRole',
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "sts:AssumeRole",
                        "Resource": "arn:aws:iam::000000000000:role/JumpRole",
                        "Effect": "Allow"
                    }
                ]
            }
        )

        iam_user_1 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }]
            },
            'admin_policy',
            'asdf1',
            '1'
        )

        iam_user_1.permissions_boundary = boundary_1

        boundary_2 = Policy(
            'arn:aws:iam::aws:policy/EmptyPolicy',
            'EmptyPolicy',
            {
                "Version": "2012-10-17",
                "Statement": []
            }
        )

        iam_user_2 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': []
            },
            'admin_policy',
            'asdf2',
            '2'
        )

        iam_user_2.permissions_boundary = boundary_2

        trust_doc = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {
                    'AWS': [
                        'arn:aws:iam::000000000000:user/asdf2',
                        'arn:aws:iam::000000000000:root'
                    ]
                },
                'Action': 'sts:AssumeRole'
            }]
        }

        self.assertTrue(
            local_check_authorization_full(
                iam_user_1,
                'sts:AssumeRole',
                'arn:aws:iam::000000000000:role/JumpRole',
                {},
                trust_doc,
                '000000000000'
            )
        )

        self.assertTrue(
            local_check_authorization_full(
                iam_user_2,
                'sts:AssumeRole',
                'arn:aws:iam::000000000000:role/JumpRole',
                {},
                trust_doc,
                '000000000000'
            )
        )
