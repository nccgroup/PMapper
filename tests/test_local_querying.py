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
            Null, ForAnyValue:Null, ForAllValues:Null

            Validated against the Simulator API
        """

        # Basic use validation
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
                                'aws:username': 'true',  # aws:username MUST NOT be present
                                'aws:userid': 'false'    # aws:userid MUST be present
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
        self.assertFalse(
            is_authorized_for(
                None,
                test_node_null,
                'iam:CreateUser',
                '*',
                {'aws:userid': '', 'aws:username': ''},
                False,
                True
            )
        )

        # ForAllValues: validation
        test_node_null_forallvalues_1 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'ForAllValues:Null': {        # For all valid context values...
                                'aws:username': 'false',  # aws:username MUST be present
                            }
                        }
                    }
                ]
            }
        )
        self.assertTrue(
            is_authorized_for(
                None,
                test_node_null_forallvalues_1,
                'iam:CreateUser',
                '*',
                {'aws:username': 'asdf'},
                False,
                True
            )
        )
        self.assertTrue(
            is_authorized_for(
                None,
                test_node_null_forallvalues_1,
                'iam:CreateUser',
                '*',
                {'aws:username': ''},
                False,
                True
            )
        )
        test_node_null_forallvalues_2 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'ForAllValues:Null': {       # For all valid context values...
                                'aws:username': 'true',  # aws:username MUST NOT be present
                            }
                        }
                    }
                ]
            }
        )
        self.assertFalse(
            is_authorized_for(
                None,
                test_node_null_forallvalues_2,
                'iam:CreateUser',
                '*',
                {'aws:username': 'asdf'},
                False,
                True
            )
        )
        self.assertTrue(
            is_authorized_for(
                None,
                test_node_null_forallvalues_2,
                'iam:CreateUser',
                '*',
                {'aws:username': ''},
                False,
                True
            )
        )

        # ForAnyValue: validation
        test_node_null_foranyvalue_1 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'ForAnyValue:Null': {        # Among the valid context values...
                                'aws:username': 'true',  # aws:username MUST NOT be present
                            }
                        }
                    }
                ]
            }
        )
        self.assertFalse(
            is_authorized_for(
                None,
                test_node_null_foranyvalue_1,
                'iam:CreateUser',
                '*',
                {'aws:username': 'asdf'},
                False,
                True
            )
        )
        self.assertFalse(
            is_authorized_for(
                None,
                test_node_null_foranyvalue_1,
                'iam:CreateUser',
                '*',
                {'aws:username': ''},
                False,
                True
            )
        )

        test_node_null_foranyvalue_2 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'ForAnyValue:Null': {         # Among the valid context values...
                                'aws:username': 'false',  # aws:username MUST be present
                            }
                        }
                    }
                ]
            }
        )
        self.assertTrue(
            is_authorized_for(
                None,
                test_node_null_foranyvalue_2,
                'iam:CreateUser',
                '*',
                {'aws:username': 'asdf'},
                False,
                True
            )
        )
        self.assertFalse(
            is_authorized_for(
                None,
                test_node_null_foranyvalue_2,
                'iam:CreateUser',
                '*',
                {'aws:username': ''},
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
