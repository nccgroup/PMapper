"""Python code for handling AWS IAM groups"""


from principalmapper.util import arns


class Group(object):
    """A class representing a single IAM group"""

    def __init__(self, arn: str = None, attached_policies: list = None):
        """Constructor"""
        if arn is None or arns.get_resource(arn)[:6] != 'group/':
            raise ValueError('Group objects must be constructed with a valid ARN for a group')
        self.arn = arn

        if attached_policies is None:
            self.attached_policies = []
        else:
            self.attached_policies = attached_policies
