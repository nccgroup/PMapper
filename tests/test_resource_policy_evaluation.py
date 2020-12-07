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

"""Test functions for local resource policy evaluation (S3 bucket policies, IAM Role Trust Docs, etc.)"""

import unittest

from tests.build_test_graphs import *
from tests.build_test_graphs import _build_user_with_policy

from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.querying.query_interface import local_check_authorization_with_resource_policy


class LocalResourcePolicyEvalTests(unittest.TestCase):
    def test_iam_assume_role(self):
        """Test that we are correctly validating policies for calls to `sts:AssumeRole`"""
        trust_doc_1 = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {
                    'AWS': 'arn:aws:iam::000000000000:root'
                },
                'Action': 'sts:AssumeRole'
            }]
        }

        trust_doc_2 = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {
                    'AWS': 'arn:aws:iam::999999999999:root'
                },
                'Action': 'sts:AssumeRole'
            }]
        }

        iam_user_1 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Resource': '*'
                }]
            },
            'single_user_policy',
            'asdf1',
            '1'
        )

        iam_user_2 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': 's3:GetObject',
                    'Resource': '*'
                }]
            },
            'single_user_policy',
            'asdf2',
            '2'
        )

        # account root + iam policy => authorized
        self.assertTrue(
            local_check_authorization_with_resource_policy(
                iam_user_1,
                'sts:AssumeRole',
                'arn:aws:iam::000000000000:role/test1',
                {},
                trust_doc_1,
                '000000000000'
            )
        )

        # iam policy only => not authorized
        self.assertFalse(
            local_check_authorization_with_resource_policy(
                iam_user_1,
                'sts:AssumeRole',
                'arn:aws:iam::000000000000:role/test1',
                {},
                trust_doc_2,
                '000000000000'
            )
        )

        # account root only => not authorized
        self.assertFalse(
            local_check_authorization_with_resource_policy(
                iam_user_2,
                'sts:AssumeRole',
                'arn:aws:iam::000000000000:role/test1',
                {},
                trust_doc_1,
                '000000000000'
            )
        )

        # Neither the account root nor the iam policy => not authorized
        self.assertFalse(
            local_check_authorization_with_resource_policy(
                iam_user_2,
                'sts:AssumeRole',
                'arn:aws:iam::000000000000:role/test1',
                {},
                trust_doc_2,
                '000000000000'
            )
        )

    def test_match_action_resource_policy_elements(self):
        """Test if we're correctly testing Action/Resource elements in resource policies"""
        bucket_policy_1 = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': '*',
                'Action': 's3:GetObject',
                'Resource': 'arn:aws:s3:::bucket/object'
            }]
        }

        bucket_policy_2 = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Deny',
                'Principal': '*',
                'Action': 's3:GetObject',
                'Resource': 'arn:aws:s3:::bucket/object'
            }]
        }

        iam_user_1 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': 's3:GetObject',
                    'Resource': 'arn:aws:s3:::bucket/object'
                }]
            },
            'single_user_policy',
            'asdf1',
            '1'
        )

        iam_user_2 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': 's3:GetObject',
                    'Resource': 'arn:aws:s3:::bucket/object'
                }]
            },
            'single_user_policy',
            'asdf2',
            '2'
        )

        rpa_result = resource_policy_authorization(
            iam_user_1,
            '000000000000',
            bucket_policy_1,
            's3:GetObject',
            'arn:aws:s3:::bucket/object',
            {}
        )
        self.assertTrue(
            rpa_result == ResourcePolicyEvalResult.NODE_MATCH
        )

        rpa_result = resource_policy_authorization(
            iam_user_1,
            '000000000000',
            bucket_policy_1,
            's3:PutObject',
            'arn:aws:s3:::bucket/object',
            {}
        )
        self.assertTrue(
            rpa_result == ResourcePolicyEvalResult.NO_MATCH
        )
