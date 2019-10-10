"""Test code for the edge-identifying functions and classes"""

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

from principalmapper.common.graphs import Graph
from principalmapper.common.nodes import Node
from principalmapper.graphing.edge_identification import obtain_edges
from principalmapper.querying.query_utils import get_search_list, is_connected
from tests.build_test_graphs import build_playground_graph


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
        other_jump_user = graph.get_node_by_searchable_name('user/some_other_jumpuser')
        other_assumable_role = graph.get_node_by_searchable_name('role/somerole')
        nonassumable_role_node = graph.get_node_by_searchable_name('role/external_s3_access_role')
        self.assertTrue(is_connected(graph, admin_user_node, jump_user))
        self.assertTrue(is_connected(graph, admin_user_node, nonassumable_role_node))
        self.assertTrue(is_connected(graph, other_jump_user, other_assumable_role))
