"""Test functions for querying (local)"""

import unittest

from tests.build_test_graphs import *
from tests.build_test_graphs import _build_user_with_policy
from principalmapper.querying.query_interface import local_check_authorization, has_matching_statement, _infer_condition_keys


class LocalQueryingTests(unittest.TestCase):
    def test_admin_can_do_anything(self):
        graph = build_graph_with_one_admin()
        principal = graph.nodes[0]
        self.assertTrue(local_check_authorization(principal, 'iam:PutUserPolicy', '*', {}, True))
        self.assertTrue(local_check_authorization(principal, 'iam:PutUserPolicy', principal.arn, {}, True))
        self.assertTrue(local_check_authorization(principal, 'iam:CreateRole', '*', {}, True))
        self.assertTrue(local_check_authorization(principal, 'sts:AssumeRole', '*', {}, True))

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

    def test_arn_condition(self):
        """ Validate the following conditions are correctly handled:
            ArnEquals, ArnLike, ArnNotEquals, ArnNotLike.

            Note, ArnEquals and ArnLike have the same behavior, as well as ArnNotEquals and ArnNotLike

            Validated against the Simulator API
        """

        # ArnEquals (and ArnLike) testing: no wildcards
        test_arn_equals = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'ArnEquals': {
                                'aws:SourceArn': 'arn:aws:iam::000000000000:user/test1',
                            }
                        }
                    }
                ]
            }
        )
        self.assertTrue(
            local_check_authorization(
                test_arn_equals, 'iam:CreateUser', '*', {'aws:SourceArn': 'arn:aws:iam::000000000000:user/test1'}, True
            )
        )
        self.assertFalse(
            local_check_authorization(
                test_arn_equals, 'iam:CreateUser', '*', {'aws:SourceArn': 'arn:aws:iam::000000000000:user/test2'}, True
            )
        )

        # ArnEquals (and ArnLike) testing: wildcards
        test_arn_equals_wild = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'ArnEquals': {
                                'aws:SourceArn': 'arn:aws:iam::*:user/test1',
                            }
                        }
                    }
                ]
            }
        )
        self.assertTrue(
            local_check_authorization(
                test_arn_equals_wild, 'iam:CreateUser', '*', {'aws:SourceArn': 'arn:aws:iam::000000000000:user/test1'},
                True
            )
        )
        self.assertFalse(
            local_check_authorization(
                test_arn_equals_wild, 'iam:CreateUser', '*', {'aws:SourceArn': 'arn:aws:iam::000000000000:user/test2'},
                True
            )
        )

        # ArnNotEquals (and ArnNotLike) testing: wildcards
        test_arn_equals_wild = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'ArnNotLike': {
                                'aws:SourceArn': 'arn:aws:iam::*:user/test1',
                            }
                        }
                    }
                ]
            }
        )
        self.assertFalse(
            local_check_authorization(
                test_arn_equals_wild, 'iam:CreateUser', '*', {'aws:SourceArn': 'arn:aws:iam::000000000000:user/test1'},
                True
            )
        )
        self.assertTrue(
            local_check_authorization(
                test_arn_equals_wild, 'iam:CreateUser', '*', {'aws:SourceArn': 'arn:aws:iam::000000000000:user/test2'},
                True
            )
        )
        self.assertFalse(
            local_check_authorization(
                test_arn_equals_wild, 'iam:CreateUser', '*', {'aws:SourceArn': 'test2'},
                True
            )
        )

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
            local_check_authorization(test_node_null, 'iam:CreateUser', '*', {'aws:userid': 'asdf', 'aws:username': ''},
                                      True)
        )
        self.assertFalse(
            local_check_authorization(test_node_null, 'iam:CreateUser', '*', {'aws:userid': '', 'aws:username': ''},
                                      True)
        )

        # Array use validation
        test_node_null_array = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'Null': {
                                'aws:username': ['true', 'false'],  # doesn't matter if it's in or not
                            }
                        }
                    }
                ]
            }
        )
        self.assertTrue(
            local_check_authorization(test_node_null_array, 'iam:CreateUser', '*', {'aws:username': ''}, True)
        )
        self.assertTrue(
            local_check_authorization(test_node_null_array, 'iam:CreateUser', '*', {'aws:username': 'asdf'}, True)
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
            local_check_authorization(test_node_null_forallvalues_1, 'iam:CreateUser', '*', {'aws:username': 'asdf'},
                                      True)
        )
        self.assertTrue(
            local_check_authorization(test_node_null_forallvalues_1, 'iam:CreateUser', '*', {'aws:username': ''}, True)
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
            local_check_authorization(test_node_null_forallvalues_2, 'iam:CreateUser', '*', {'aws:username': 'asdf'},
                                      True)
        )
        self.assertTrue(
            local_check_authorization(test_node_null_forallvalues_2, 'iam:CreateUser', '*', {'aws:username': ''}, True)
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
                                'aws:username': 'true',  # aws:username MUST NOT be present (cannot fulfill this)
                            }
                        }
                    }
                ]
            }
        )
        self.assertFalse(
            local_check_authorization(test_node_null_foranyvalue_1, 'iam:CreateUser', '*', {'aws:username': 'asdf'},
                                      True)
        )
        self.assertFalse(
            local_check_authorization(test_node_null_foranyvalue_1, 'iam:CreateUser', '*', {'aws:username': ''}, True)
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
            local_check_authorization(test_node_null_foranyvalue_2, 'iam:CreateUser', '*', {'aws:username': 'asdf'},
                                      True)
        )
        self.assertFalse(
            local_check_authorization(test_node_null_foranyvalue_2, 'iam:CreateUser', '*', {'aws:username': ''}, True)
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
        # DateEquals
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
        self.assertTrue(local_check_authorization(test_node_date_equals, 'iam:CreateUser', '*',
                                                  {'aws:CurrentTime': '2018-08-10T00:00:00Z'}, True))
        self.assertTrue(local_check_authorization(test_node_date_equals, 'iam:CreateUser', '*',
                                                  {'aws:CurrentTime': '1533859200.0'}, True))
        self.assertTrue(local_check_authorization(test_node_date_equals, 'iam:CreateUser', '*',
                                                  {'aws:CurrentTime': '1533859200'}, True))
        self.assertFalse(local_check_authorization(test_node_date_equals, 'iam:CreateUser', '*',
                                                  {'aws:CurrentTime': '1533859201'}, True))
        self.assertFalse(local_check_authorization(test_node_date_equals, 'iam:CreateUser', '*',
                                                   {'aws:CurrentTime': '2018-08-10T00:00:01Z'}, True))

        # DateNotEquals
        test_node_date_not_equals = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'DateNotEquals': {
                                'aws:CurrentTime': '2018-08-10T00:00:00Z'
                            }
                        }
                    }
                ]
            }
        )
        self.assertFalse(local_check_authorization(test_node_date_not_equals, 'iam:CreateUser', '*',
                                                  {'aws:CurrentTime': '2018-08-10T00:00:00Z'}, True))
        self.assertTrue(local_check_authorization(test_node_date_not_equals, 'iam:CreateUser', '*',
                                                   {'aws:CurrentTime': '2018-08-10T00:00:01Z'}, True))

        # DateGreaterThan
        test_node_date_greater_than = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'DateGreaterThan': {
                                'aws:CurrentTime': '2018-08-10T00:00:00Z'
                            }
                        }
                    }
                ]
            }
        )
        self.assertFalse(local_check_authorization(test_node_date_greater_than, 'iam:CreateUser', '*',
                                                   {'aws:CurrentTime': '2018-08-10T00:00:00Z'}, True))
        self.assertTrue(local_check_authorization(test_node_date_greater_than, 'iam:CreateUser', '*',
                                                  {'aws:CurrentTime': '2018-08-10T00:00:01Z'}, True))

        # DateGreaterThanEquals
        test_node_date_greater_than_equals = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'DateGreaterThanEquals': {
                                'aws:CurrentTime': '2018-08-10T00:00:00Z'
                            }
                        }
                    }
                ]
            }
        )
        self.assertFalse(local_check_authorization(test_node_date_greater_than_equals, 'iam:CreateUser', '*',
                                                  {'aws:CurrentTime': '2018-08-09T23:59:59Z'}, True))
        self.assertTrue(local_check_authorization(test_node_date_greater_than_equals, 'iam:CreateUser', '*',
                                                   {'aws:CurrentTime': '2018-08-10T00:00:00Z'}, True))
        self.assertTrue(local_check_authorization(test_node_date_greater_than_equals, 'iam:CreateUser', '*',
                                                  {'aws:CurrentTime': '2018-08-10T00:00:01Z'}, True))

        # DateLessThan
        test_node_date_less_than = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'DateLessThan': {
                                'aws:CurrentTime': '2018-08-10T00:00:00Z'
                            }
                        }
                    }
                ]
            }
        )
        self.assertTrue(local_check_authorization(test_node_date_less_than, 'iam:CreateUser', '*',
                                                   {'aws:CurrentTime': '2018-08-09T23:59:59Z'}, True))
        self.assertFalse(local_check_authorization(test_node_date_less_than, 'iam:CreateUser', '*',
                                                  {'aws:CurrentTime': '2018-08-10T00:00:01Z'}, True))

        # DateLessThanEquals
        test_node_date_less_than_equals = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'DateLessThanEquals': {
                                'aws:CurrentTime': '2018-08-10T00:00:00Z'
                            }
                        }
                    }
                ]
            }
        )
        self.assertTrue(local_check_authorization(test_node_date_less_than_equals, 'iam:CreateUser', '*',
                                                   {'aws:CurrentTime': '2018-08-09T23:59:59Z'}, True))
        self.assertTrue(local_check_authorization(test_node_date_less_than_equals, 'iam:CreateUser', '*',
                                                  {'aws:CurrentTime': '2018-08-10T00:00:00Z'}, True))
        self.assertFalse(local_check_authorization(test_node_date_less_than_equals, 'iam:CreateUser', '*',
                                                  {'aws:CurrentTime': '2018-08-10T00:00:01Z'}, True))
