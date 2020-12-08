"""Code to implement the CLI interface to the graphing component of Principal Mapper"""

#  Copyright (c) NCC Group and Erik Steringer 2020. This file is part of Principal Mapper.
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

from argparse import ArgumentParser, Namespace


def provide_arguments(parser: ArgumentParser):
    """Given a parser object (which should be a subparser), add arguments to provide a CLI interface to the
    graphing component of Principal Mapper.
    """
    command_group = parser.add_mutually_exclusive_group(required=True)
    command_group.add_argument(
        '--create',
        action='store_true',
        help='Creates a completely new graph for an AWS account, wiping away any old data.'
    )
    command_group.add_argument(
        '--display',
        action='store_true',
        help='Displays information about a currently-stored graph based on the AWS credentials used.'
    )
    command_group.add_argument(
        '--list',
        action='store_true',
        help='List the Account IDs of graphs stored on this computer.'
    )
    command_group.add_argument(
        '--update-edges',
        action='store_true',
        help='Updates the edges of an AWS account. Does not gather information about IAM users or roles.'
    )


def process_arguments(parsed_args: Namespace):
    """Given a namespace object generated from parsing args, perform the appropriate tasks."""
    pass
