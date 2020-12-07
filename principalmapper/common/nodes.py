"""Python module containing the Node class and any Node-specific utility functions (currently none)."""


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

from typing import List, Optional, Union

import principalmapper.common.edges
from principalmapper.common.groups import Group
from principalmapper.common.policies import Policy
from principalmapper.util import arns


class Node(object):
    """The basic Node object: tracks data about the IAM User/Role this Node represents. Includes the ARN, ID,
    attached policies (inline or attached), group memberships, trust doc (if IAM Role), instance profiles (if IAM Role),
    if a password is active (if IAM User), if there are active access keys (if IAM User), and if the IAM User/Role has
    administrative permissions for the account.

    * (1.1.0) Added permissions_boundary support, has_mfa support, tags support"""

    def __init__(self, arn: str, id_value: str, attached_policies: Optional[List[Policy]],
                 group_memberships: Optional[List[Group]], trust_policy: Optional[dict],
                 instance_profile: Optional[List[str]], num_access_keys: int, active_password: bool, is_admin: bool,
                 permissions_boundary: Optional[Union[str, Policy]], has_mfa: bool, tags: Optional[dict]):
        """Constructor. Expects an ARN and ID value. Validates parameters based on the type of Node (User/Role),
        and rejects contradictory arguments like an IAM User with a trust policy.
        """

        resource_value = arns.get_resource(arn)
        if arn is None or not (resource_value.startswith('user/') or resource_value.startswith('role/')):
            raise ValueError('The parameter arn must be a valid ARN for an IAM user or role.')
        self.arn = arn

        if id_value is None or len(id_value) == 0:
            raise ValueError('The parameter id_value must be a non-empty string.')
        self.id_value = id_value

        if attached_policies is None:
            self.attached_policies = []
        else:
            self.attached_policies = attached_policies

        if group_memberships is None:
            self.group_memberships = []
        else:
            self.group_memberships = group_memberships

        if resource_value.startswith('user/') and trust_policy is not None:
            raise ValueError('IAM users do not have trust policies, pass None for the parameter trust_policy.')
        if resource_value.startswith('role/') and (trust_policy is None or not isinstance(trust_policy, dict)):
            raise ValueError('IAM roles have trust policies, which must be passed as a dictionary in trust_policy')
        self.trust_policy = trust_policy  # None denotes no trust policy (not a role), {} denotes empty trust policy

        if resource_value.startswith('user/') and instance_profile is not None:
            raise ValueError('IAM users do not have instance profiles. Pass None for the parameter instance_profile.')
        self.instance_profile = instance_profile

        self.active_password = active_password

        if num_access_keys is None:
            self.access_keys = []
        else:
            self.access_keys = num_access_keys

        self.is_admin = is_admin

        self.permissions_boundary = permissions_boundary  # None denotes no permissions boundary, str denotes need to fill in

        self.has_mfa = has_mfa

        if tags is None:
            self.tags = {}
        else:
            self.tags = tags

        self.cache = {}

    def searchable_name(self) -> str:
        """Creates and caches the searchable name of this node. First it splits the user/.../name into its
        parts divided by slashes, then returns the first and last element. The last element is supposed to be unique
        within users and roles (RoleName/--role-name or UserName/--user-name parameter when using the API/CLI).
        """
        if 'searchable_name' not in self.cache:
            components = arns.get_resource(self.arn).split('/')
            self.cache['searchable_name'] = "{}/{}".format(components[0], components[-1])
        return self.cache['searchable_name']

    def get_outbound_edges(self, graph):  # -> List[Edge], can't import Edge/Graph in this module
        """Creates and caches a collection of edges where this (self) Node is the source."""
        if 'outbound_edges' not in self.cache:
            self.cache['outbound_edges'] = []
            if self.is_admin:
                for node in graph.nodes:
                    if node == self:
                        continue
                    else:
                        self.cache['outbound_edges'].append(
                            principalmapper.common.edges.Edge(
                                self, node, 'can access through administrative actions', 'Admin'
                            )
                        )
            else:
                for edge in graph.edges:
                    if edge.source == self:
                        self.cache['outbound_edges'].append(edge)
        return self.cache['outbound_edges']

    def to_dictionary(self) -> dict:
        """Creates a dictionary representation of this Node for storage."""
        _pb = self.permissions_boundary
        if _pb is not None:
            _pb = {'arn': self.permissions_boundary.arn, 'name': self.permissions_boundary.name}
        return {
            "arn": self.arn,
            "id_value": self.id_value,
            "attached_policies": [{'arn': policy.arn, 'name': policy.name} for policy in self.attached_policies],
            "group_memberships": [group.arn for group in self.group_memberships],
            "trust_policy": self.trust_policy,
            "instance_profile": self.instance_profile,
            "active_password": self.active_password,
            "access_keys": self.access_keys,
            "is_admin": self.is_admin,
            "permissions_boundary": _pb,
            "has_mfa": self.has_mfa,
            "tags": self.tags
        }
