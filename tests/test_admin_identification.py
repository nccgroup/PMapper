#  Copyright (c) NCC Group and Erik Steringer 2021. This file is part of Principal Mapper.
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


import logging
import unittest


from principalmapper.common import Node, Policy, Group
from principalmapper.graphing.gathering import update_admin_status


class TestAdminIdentification(unittest.TestCase):
    def test_admin_verified_by_inline_policies(self):
        admin_policy = Policy('arn:aws:iam::000000000000:user/user_1', 'inline_admin', {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': '*',
                'Resource': '*'
            }]
        })

        not_admin_policy = Policy('arn:aws:iam::000000000000:user/user_2', 'inline_not_admin', {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                },
                {
                    'Effect': 'Deny',
                    'Action': '*',
                    'Resource': '*'
                }
            ]
        })

        new_node_1 = Node('arn:aws:iam::000000000000:user/user_1', 'id1', [admin_policy], [], None, None, 1, False,
                          False, None, False, None)
        new_node_2 = Node('arn:aws:iam::000000000000:user/user_2', 'id2', [not_admin_policy], [], None, None, 1, False,
                          False, None, False, None)

        update_admin_status([new_node_1, new_node_2])

        self.assertTrue(new_node_1.is_admin, 'User with admin policy should be marked as an admin')
        self.assertFalse(new_node_2.is_admin, 'User with non-admin policy should not be marked as an admin')

    def test_admin_verified_for_group_member(self):
        admin_policy = Policy('arn:aws:iam::000000000000:group/admins', 'inline_admin', {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': '*',
                'Resource': '*'
            }]
        })

        admin_group = Group('arn:aws:iam::000000000000:group/admins', [admin_policy])
        not_admin_group = Group('arn:aws:iam::000000000000:group/losers', [])

        new_node_1 = Node('arn:aws:iam::000000000000:user/node_1', 'id1', [], [admin_group], None, None, 1, False,
                          False, None, False, None)
        new_node_2 = Node('arn:aws:iam::000000000000:user/node_2', 'id2', [], [not_admin_group], None, None, 1, False,
                          False, None, False, None)

        update_admin_status([new_node_1, new_node_2])

        self.assertTrue(new_node_1.is_admin, 'Member of admin group should be marked as an admin')
        self.assertFalse(new_node_2.is_admin, 'Member of non-admin group should not be marked as an admin')
