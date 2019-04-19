"""Test functions for querying (local)"""

import unittest

from .build_test_graphs import *
from principalmapper.querying.query_interface import is_authorized_for


class LocalQueryingTests(unittest.TestCase):
    def test_admin_can_do_anything(self):
        graph = build_graph_with_one_admin()
        principal = graph.nodes[0]
        self.assertTrue(is_authorized_for(None, principal, 'iam:PutUserPolicy', '*', {}, False, True))
        self.assertTrue(is_authorized_for(None, principal, 'iam:PutUserPolicy', principal.arn, {}, False, True))
        self.assertTrue(is_authorized_for(None, principal, 'iam:CreateRole', '*', {}, False, True))
