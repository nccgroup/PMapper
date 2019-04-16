"""Python code for handling AWS IAM groups"""


from principalmapper.util import arns


class Group(object):
    """A class representing a single IAM group"""

    def __init__(self, arn: str, attached_policies: list):
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
            'attached_policies': [policy.arn for policy in self.attached_policies]
        }
