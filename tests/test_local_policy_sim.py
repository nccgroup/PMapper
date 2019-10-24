"""Test functions for local policy simulation"""

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

import unittest

from principalmapper.querying.local_policy_simulation import _matches_after_expansion, _statement_matches_action, _statement_matches_resource


class TestLocalPolicyStatementMatching(unittest.TestCase):
    def test_action_matching(self):
        statement_1 = {
            'Effect': 'Allow',
            'Action': ['ec2:RunInstances', 's3:*', 'iam:Get*'],
            'Resource': '*'
        }
        self.assertTrue(_statement_matches_action(statement_1, 'ec2:RunInstances'))
        self.assertTrue(_statement_matches_action(statement_1, 's3:GetObject'))
        self.assertTrue(_statement_matches_action(statement_1, 'iam:GetRole'))
        self.assertFalse(_statement_matches_action(statement_1, 'ec2:DescribeInstances'))
        self.assertFalse(_statement_matches_action(statement_1, 'iam:PutRolePolicy'))

        statement_2 = {
            'Effect': 'Allow',
            'Action': '*',
            'Resource': '*'
        }
        self.assertTrue(_statement_matches_action(statement_2, 'iam:GetRole'))

        statement_3 = {
            'Effect': 'Allow',
            'NotAction': '*',
            'Resource': '*'
        }
        self.assertFalse(_statement_matches_action(statement_3, 'iam:GetRole'))

        statement_4 = {
            'Effect': 'Allow',
            'NotAction': ['iam:*', 's3:Put*'],
            'Resource': '*'
        }
        self.assertFalse(_statement_matches_action(statement_4, 'iam:GetRole'))
        self.assertFalse(_statement_matches_action(statement_4, 's3:PutObject'))
        self.assertTrue(_statement_matches_action(statement_4, 'ec2:RunInstances'))

    def test_resource_matching(self):
        statement_1 = {
            'Effect': 'Allow',
            'Action': '*',
            'Resource': ['arn:aws:s3:::bucket/*', 'arn:aws:s3:::*/object', 'arn:aws:s3:::${aws:SourceAccount}/win']
        }
        self.assertTrue(_statement_matches_resource(statement_1, 'arn:aws:s3:::bucket/anything'))
        self.assertTrue(_statement_matches_resource(statement_1, 'arn:aws:s3:::anything/object'))
        self.assertTrue(_statement_matches_resource(statement_1, 'arn:aws:s3:::000000000000/win', {'aws:SourceAccount': '000000000000'}))

        statement_2 = {
            'Effect': 'Allow',
            'Action': '*',
            'NotResource': ['arn:aws:s3:::bucket/*', 'arn:aws:s3:::*/object', 'arn:aws:s3:::${aws:SourceAccount}/win']
        }
        self.assertFalse(_statement_matches_resource(statement_2, 'arn:aws:s3:::bucket/anything'))
        self.assertFalse(_statement_matches_resource(statement_2, 'arn:aws:s3:::anything/object'))
        self.assertFalse(_statement_matches_resource(statement_2, 'arn:aws:s3:::000000000000/win',
                                                     {'aws:SourceAccount': '000000000000'}))


class TestLocalPolicyVariableExpansions(unittest.TestCase):
    def test_var_expansion(self):
        self.assertTrue(_matches_after_expansion(
            'arn:aws:iam::000000000000:user/test',
            'arn:aws:iam::000000000000:user/${aws:username}',
            {'aws:username': 'test'},
            True
        ))

    def test_asterisk_expansion(self):
        self.assertTrue(_matches_after_expansion(
            'test-123',
            'test*',
            None,
            True
        ))
        self.assertTrue(_matches_after_expansion(
            'test',
            'test*',
            None,
            True
        ))
        self.assertFalse(_matches_after_expansion(
            'tset',
            'test*',
            None,
            True
        ))

    def test_qmark_expansion(self):
        self.assertTrue(_matches_after_expansion(
            'test-1',
            'test-?',
            None,
            True
        ))
        self.assertFalse(_matches_after_expansion(
            'test1',
            'test-?',
            None,
            True
        ))
