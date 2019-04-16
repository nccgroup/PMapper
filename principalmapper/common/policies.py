"""Python code for handling AWS IAM policies"""


class Policy(object):
    """A class representing a single IAM policy"""

    def __init__(self, arn: str, name: str, policy_doc: dict):
        """Constructor.

        Expects an ARN with either :user/, :role/, :group/, or :policy/ in it (tracked as managed or inline this way)
        Expects a dictionary for the policy document parameter, so you must parse the JSON beforehand
        """
        if arn is None or \
                (':user/' not in arn and ':role/' not in arn and ':group/' not in arn and ':policy/' not in arn):
            raise ValueError('The parameter arn must be a string representing a principal or policy ARN')
        if policy_doc is None or not isinstance(policy_doc, dict):
            raise ValueError('Policy objects must be constructed with a dictionary policy_doc parameter')

        self.arn = arn
        self.name = name
        self.policy_doc = policy_doc

    def to_dictionary(self):
        """Returns a dictionary representation of this object for storage"""
        return {
            'arn': self.arn,
            'name': self.name,
            'policy_doc': self.policy_doc
        }
