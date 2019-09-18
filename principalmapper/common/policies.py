"""Python module containing the Policy class and any Policy-specific utility functions (currently none)."""


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

class Policy(object):
    """The basic Policy object: tracks data about the IAM Policy this represents. This includes who the policy
    is attached to (arn is the IAM User/Role for inline, policy ARN otherwose), what its name is (inline),
    and the contents of the policy (in dictionary form)."""

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

    def to_dictionary(self) -> dict:
        """Returns a dictionary representation of this object for storage"""
        return {
            'arn': self.arn,
            'name': self.name,
            'policy_doc': self.policy_doc
        }
