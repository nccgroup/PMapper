"""Python code for implementing the nodes of a graph"""

from typing import List, Optional

from principalmapper.common.groups import Group
from principalmapper.common.policies import Policy
from principalmapper.util import arns


class Node(object):
    """The basic Node object"""

    def __init__(self, arn: str, id_value: str, attached_policies: Optional[List[Policy]], group_memberships: Optional[List[Group]],
                 trust_policy: Optional[dict], instance_profile: Optional[str], num_access_keys: int,
                 active_password: bool, is_admin: bool):
        """Constructor"""

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

        self.cache = {}

    def searchable_name(self):
        """Creates and caches the searchable name of this node. First it splits the user/.../name into its
        parts divided by slashes, then returns the first and last element. The last element is supposed to be unique
        within users and roles.
        """
        if 'searchable_name' not in self.cache:
            components = arns.get_resource(self.arn).split('/')
            self.cache['searchable_name'] = "{}/{}".format(components[0], components[-1])
        return self.cache['searchable_name']

    def to_dictionary(self):
        """Creates a dictionary representation of this Node for storage"""
        return {
            "arn": self.arn,
            "id_value": self.id_value,
            "attached_policies": [{'arn': policy.arn, 'name': policy.name} for policy in self.attached_policies],
            "group_memberships": [group.arn for group in self.group_memberships],
            "trust_policy": self.trust_policy,
            "instance_profile": self.instance_profile,
            "active_password": self.active_password,
            "access_keys": self.access_keys,
            "is_admin": self.is_admin
        }
