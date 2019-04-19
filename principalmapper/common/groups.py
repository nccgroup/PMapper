"""Python code for handling AWS IAM groups"""

from typing import List
from typing import Optional

from principalmapper.common.policies import Policy
from principalmapper.util import arns


class Group(object):
    """A class representing a single IAM group"""

    def __init__(self, arn: str, attached_policies: Optional[List[Policy]]):
        """Constructor"""
        if arn is None or not arns.get_resource(arn).startswith('group/'):
            raise ValueError('Group objects must be constructed with a valid ARN for a group')
        self.arn = arn

        if attached_policies is None:
            self.attached_policies = []
        else:
            self.attached_policies = attached_policies

    def to_dictionary(self):
        """Returns a dictionary representation of this object for storage"""
        return {
            'arn': self.arn,
            'attached_policies': [{'arn': policy.arn, 'name': policy.name} for policy in self.attached_policies]
        }
