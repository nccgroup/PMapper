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

import logging
import sys


logger = logging.getLogger(__name__)


def dprint(debugging: bool, message: str) -> None:
    """DEPRECATED AS OF v1.1.0 DURING LOGGING OVERHAUL.

    Prints message to stderr if debugging, newline is automatically appended"""
    logger.warning('The `dprint` function is deprecated, and should not be used.')
    if debugging:
        sys.stderr.write(message)
        sys.stderr.write("\n")


def dwrite(debugging: bool, message: str) -> None:
    """DEPRECATED AS OF v1.1.0 DURING LOGGING OVERHAUL.

    Writes message to stderr if debugging (no newline at the end)"""
    logger.warning('The `dwrite` function is deprecated, and should not be used.')
    if debugging:
        sys.stderr.write(message)
