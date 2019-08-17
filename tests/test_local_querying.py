"""Test functions for querying (local)"""

import unittest

from tests.build_test_graphs import *
from tests.build_test_graphs import _build_user_with_policy
from principalmapper.querying.query_interface import is_authorized_for, has_matching_statement, _infer_condition_keys


class LocalQueryingTests(unittest.TestCase):
    def test_admin_can_do_anything(self):
        graph = build_graph_with_one_admin()
        principal = graph.nodes[0]
        self.assertTrue(is_authorized_for(None, principal, 'iam:PutUserPolicy', '*', {}, False, True))
        self.assertTrue(is_authorized_for(None, principal, 'iam:PutUserPolicy', principal.arn, {}, False, True))
        self.assertTrue(is_authorized_for(None, principal, 'iam:CreateRole', '*', {}, False, True))
        self.assertTrue(is_authorized_for(None, principal, 'sts:AssumeRole', '*', {}, False, True))

    def test_condition_key_handling_in_resources(self):
        test_node = _build_user_with_policy({
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': 'iam:CreateAccessKey',
                'Resource': 'arn:aws:iam::000000000000:user/${aws:username}'
            }]
        })

        self.assertTrue(has_matching_statement(test_node, 'Allow', 'iam:CreateAccessKey', test_node.arn,
                                               {'aws:username': 'asdf'}, True))

    def test_inferred_keys(self):
        test_node = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }]
            },
            user_name='infer'
        )

        inferred_keys = _infer_condition_keys(test_node, {})
        self.assertTrue('aws:username' in inferred_keys)
        self.assertTrue(inferred_keys['aws:username'] == 'infer')

    def test_null_condition_handling(self):
        """ Validate the following conditions are correctly handled:
            Null
        """
        test_node_null = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'Null': {
                                'aws:username': 'false',
                                'aws:userid': 'true'
                            }
                        }
                    }
                ]
            }
        )
        self.assertTrue(
            is_authorized_for(
                None,
                test_node_null,
                'iam:CreateUser',
                '*',
                {'aws:userid': 'asdf', 'aws:username': ''},
                False,
                True
            )
        )

    def test_datetime_condition_handling(self):
        """ Validate the following conditions are correctly handled:
            DateEquals
            DateNotEquals
            DateLessThan
            DateLessThanEquals
            DateGreaterThan
            DateGreaterThanEquals
        """
        test_node_date_equals = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'DateEquals': {
                                'aws:CurrentTime': '2018-08-10T00:00:00Z'
                            }
                        }
                    }
                ]
            }
        )

        self.assertTrue(is_authorized_for(
            None,
            test_node_date_equals,
            'iam:CreateUser',
            '*',
            {'aws:CurrentTime': '2018-08-10T00:00:00Z'},
            False,
            True
        ))

        self.assertFalse(is_authorized_for(
            None,
            test_node_date_equals,
            'iam:CreateUser',
            '*',
            {'aws:CurrentTime': '2018-08-10T00:00:01Z'},
            False,
            True
        ))
