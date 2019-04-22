"""Code for testing the constructors of graphs, nodes, edges, policies, and groups"""

import unittest

from principalmapper.common.graphs import Graph
from principalmapper.common.nodes import Node


class ConstructorTest(unittest.TestCase):
    def test_graphs(self):
        with self.assertRaises(ValueError):
            Graph(nodes=None, edges=[], policies=[], groups=[])
        with self.assertRaises(ValueError):
            Graph(nodes=[], edges=None, policies=[], groups=[])
        with self.assertRaises(ValueError):
            Graph(nodes=[], edges=[], policies=None, groups=[])
        with self.assertRaises(ValueError):
            Graph(nodes=[], edges=[], policies=[], groups=None)

    def test_nodes(self):
        with self.assertRaises(ValueError):
            Node(arn='arn:aws:iam::000000000000:group/notauser', attached_policies=[], group_memberships=[],
                 trust_policy=None, instance_profile=None, num_access_keys=0, active_password=False, is_admin=False)
        try:
            Node(arn='arn:aws:iam::000000000000:user/auser', attached_policies=[], group_memberships=[],
                 trust_policy=None, instance_profile=None, num_access_keys=0, active_password=False, is_admin=False)
        except Exception as ex:
            self.fail('Unexpected error: ' + str(ex))
