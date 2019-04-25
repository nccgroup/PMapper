"""Test code for the edge-identifying functions and classes"""

import unittest

from principalmapper.common.graphs import Graph
from principalmapper.common.nodes import Node
from principalmapper.graphing.edge_identification import obtain_edges
from principalmapper.querying.query_utils import get_search_list, is_connected
from .build_test_graphs import build_playground_graph


class TestEdgeIdentification(unittest.TestCase):
    def test_playground_assume_role(self):
        graph = build_playground_graph()
        jump_user_node = graph.get_node_by_searchable_name('user/jumpuser')
        assumable_s3_role_node = graph.get_node_by_searchable_name('role/s3_access_role')
        assumable_s3_role_node_alt = graph.get_node_by_searchable_name('role/s3_access_role_alt')
        nonassumable_role_node = graph.get_node_by_searchable_name('role/external_s3_access_role')
        self.assertTrue(is_connected(graph, jump_user_node, assumable_s3_role_node))
        self.assertTrue(is_connected(graph, jump_user_node, assumable_s3_role_node_alt))
        self.assertFalse(is_connected(graph, jump_user_node, nonassumable_role_node))

    def test_admin_access(self):
        graph = build_playground_graph()
        admin_user_node = graph.get_node_by_searchable_name('user/admin')
        jump_user = graph.get_node_by_searchable_name('user/jumpuser')
        nonassumable_role_node = graph.get_node_by_searchable_name('role/external_s3_access_role')
        self.assertTrue(is_connected(graph, admin_user_node, jump_user))
        self.assertTrue(is_connected(graph, admin_user_node, nonassumable_role_node))
