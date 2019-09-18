"""Code for handling printing to console depending on if debugging is enabled"""

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

import sys


def dprint(debugging: bool, message: str) -> None:
    """Prints message to console if debugging"""
    if debugging:
        sys.stderr.write(message)
        sys.stderr.write("\n")


def dwrite(debugging: bool, message: str) -> None:
    """Writes message to console if debugging (no newline at the end)"""
    if debugging:
        sys.stderr.write(message)
