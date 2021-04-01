"""Code to implement the CLI interface to the analysis component of Principal Mapper"""

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

from principalmapper.analysis import find_risks
from principalmapper.graphing import graph_actions
from principalmapper.util import botocore_tools


def provide_arguments(parser: ArgumentParser):
    """Given a parser object (which should be a subparser), add arguments to provide a CLI interface to the
    analysis component of Principal Mapper.
    """
    parser.add_argument(
        '--output-type',
        default='text',
        choices=['text', 'json'],
        help='The type of output for identified issues.'
    )


def process_arguments(parsed_args: Namespace) -> int:
    """Given a namespace object generated from parsing args, perform the appropriate tasks. Returns an int
    matching expectations set by /usr/include/sysexits.h for command-line utilities."""

    if parsed_args.account is None:
        session = botocore_tools.get_session(parsed_args.profile)
    else:
        session = None
    graph = graph_actions.get_existing_graph(session, parsed_args.account)

    find_risks.gen_findings_and_print(graph, parsed_args.output_type)

    return 0
