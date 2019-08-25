"""Test functions for local policy simulation"""

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

import unittest

from principalmapper.querying.local_policy_simulation import _matches_after_expansion


class TestLocalPolicySimulation(unittest.TestCase):
    def test_var_expansion(self):
        self.assertTrue(_matches_after_expansion(
            'arn:aws:iam::000000000000:user/test',
            'arn:aws:iam::000000000000:user/${aws:username}',
            {'aws:username': 'test'},
            True
        ))

    def test_asterisk_expansion(self):
        self.assertTrue(_matches_after_expansion(
            'test-123',
            'test*',
            None,
            True
        ))
        self.assertTrue(_matches_after_expansion(
            'test',
            'test*',
            None,
            True
        ))
        self.assertFalse(_matches_after_expansion(
            'tset',
            'test*',
            None,
            True
        ))

    def test_qmark_expansion(self):
        self.assertTrue(_matches_after_expansion(
            'test-1',
            'test-?',
            None,
            True
        ))
        self.assertFalse(_matches_after_expansion(
            'test1',
            'test-?',
            None,
            True
        ))
