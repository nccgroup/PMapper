"""Python code for implementing the nodes of a graph"""

from typing import Optional

from principalmapper.util import arns


class Node(object):
    """The basic Node object"""

    def __init__(self, arn: str, attached_policies: Optional[list], group_memberships: Optional[list],
                 trust_policy: Optional[dict], num_access_keys: int, active_password: bool, is_admin: bool):
        """Constructor"""

        resource_value = arns.get_resource(arn)
        if arn is None or not (resource_value.startswith('user/') or resource_value.startswith('role/')):
            raise ValueError('The parameter arn must be a valid ARN for an IAM user or role.')
        self.arn = arn

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

        self.active_password = active_password

        if num_access_keys is None:
            self.access_keys = []
        else:
            self.access_keys = num_access_keys

        self.is_admin = is_admin

    def to_dictionary(self):
        """Creates a dictionary representation of this Node for storage"""
        return {
            "arn": self.arn,
            "attached_policies": [{'arn': policy.arn, 'name': policy.name} for policy in self.attached_policies],
            "group_memberships": [group.arn for group in self.group_memberships],
            "trust_policy": self.trust_policy,
            "active_password": self.active_password,
            "access_keys": self.access_keys,
            "is_admin": self.is_admin
        }
