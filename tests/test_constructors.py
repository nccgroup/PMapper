"""Code for testing the constructors of graphs, nodes, edges, policies, and groups"""


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
            Node(arn='arn:aws:iam::000000000000:group/notauser', id_value='AIDA00000000000000000', attached_policies=[],
                 group_memberships=[], trust_policy=None, instance_profile=None, num_access_keys=0,
                 active_password=False, is_admin=False)
        try:
            Node(arn='arn:aws:iam::000000000000:user/auser', id_value='AIDA00000000000000001', attached_policies=[],
                 group_memberships=[], trust_policy=None, instance_profile=None, num_access_keys=0,
                 active_password=False, is_admin=False)
        except Exception as ex:
            self.fail('Unexpected error: ' + str(ex))
