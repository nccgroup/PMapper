"""Test functions for local policy simulation"""

import unittest

from principalmapper.querying.local_policy_simulation import _matches_after_expansion


class TestLocalPolicySimulation(unittest.TestCase):
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
