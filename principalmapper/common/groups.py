"""Python code for handling AWS IAM groups"""



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
