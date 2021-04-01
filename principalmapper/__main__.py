"""
Provides a command-line interface to use the principalmapper library
"""

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

import argparse
import logging
import sys

from principalmapper.analysis import cli as analysis_cli
from principalmapper.graphing import graph_cli
from principalmapper.graphing import orgs_cli
from principalmapper.querying import query_cli
from principalmapper.querying import argquery_cli
from principalmapper.querying import repl_cli
from principalmapper.visualizing import cli as visualizing_cli


logger = logging.getLogger(__name__)


def main() -> int:
    """Point of entry for command-line"""
    argument_parser = argparse.ArgumentParser(prog='pmapper')
    argument_parser.add_argument(
        '--profile',
        help='The AWS CLI (botocore) profile to use to call the AWS API.'
    )  # Note: do NOT set the default, we want to know if the profile arg was specified or not
    argument_parser.add_argument(
        '--account',
        help='When running offline operations, this parameter determines which account to act against.'
    )
    argument_parser.add_argument(
        '--debug',
        action='store_true',
        help='Produces debug-level output of the underlying Principal Mapper library during execution.'
    )

    # Create subparser for various subcommands
    subparser = argument_parser.add_subparsers(
        title='subcommand',
        description='The subcommand to use among this suite of tools',
        dest='picked_cmd',
        help='Select a subcommand to execute'
    )

    # Graph subcommand
    graphparser = subparser.add_parser(
        'graph',
        description='Obtains information about a specific AWS account\'s use of IAM for analysis.',
        help='Pulls information for an AWS account\'s use of IAM.'
    )
    graph_cli.provide_arguments(graphparser)

    # Organizations subcommand
    orgsparser = subparser.add_parser(
        'orgs',
        description='Obtains information about an AWS Organization for further analysis.',
        help='Pulls information for an AWS Organization'
    )
    orgs_cli.provide_arguments(orgsparser)

    # Query subcommand
    queryparser = subparser.add_parser(
        'query',
        description='Displays information corresponding to a roughly human-readable query.',
        help='Displays information corresponding to a query'
    )
    query_cli.provide_arguments(queryparser)

    # Argquery subcommand
    argqueryparser = subparser.add_parser(
        'argquery',
        description='Displays information corresponding to a arg-specified query.',
        help='Displays information corresponding to a query'
    )
    argquery_cli.provide_arguments(argqueryparser)

    # REPL subcommand
    replparser = subparser.add_parser(
        'repl',
        description='Runs a read-evaluate-print-loop of queries, avoiding the need to read from disk for each query',
        help='Runs a REPL for querying'
    )

    # Visualization subcommand
    visualizationparser = subparser.add_parser(
        'visualize',
        description='Generates an image file to display information about an AWS account',
        help='Generates an image representing the AWS account'
    )
    visualizing_cli.provide_arguments(visualizationparser)

    # Analysis subcommand
    analysisparser = subparser.add_parser(
        'analysis',
        description='Analyzes and reports identified issues',
        help='Analyzes and reports identified issues'
    )
    analysis_cli.provide_arguments(analysisparser)

    parsed_args = argument_parser.parse_args()

    # setup our outputs here
    if parsed_args.debug:
        logging.basicConfig(
            format='%(asctime)s | %(levelname)8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S%z',
            level=logging.DEBUG,
            handlers=[
                logging.StreamHandler(sys.stdout)
            ]
        )
    else:
        logging.basicConfig(
            format='%(asctime)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S%z',
            level=logging.INFO,
            handlers=[
                logging.StreamHandler(sys.stdout)
            ]
        )

    # we don't wanna hear from these loggers, even during debugging, due to the sheer volume of output
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('principalmapper.querying.query_interface').setLevel(logging.WARNING)

    logger.debug('Parsed args: {}'.format(parsed_args))
    if parsed_args.picked_cmd == 'graph':
        return graph_cli.process_arguments(parsed_args)
    elif parsed_args.picked_cmd == 'orgs':
        return orgs_cli.process_arguments(parsed_args)
    elif parsed_args.picked_cmd == 'query':
        return query_cli.process_arguments(parsed_args)
    elif parsed_args.picked_cmd == 'argquery':
        return argquery_cli.process_arguments(parsed_args)
    elif parsed_args.picked_cmd == 'repl':
        return repl_cli.process_arguments(parsed_args)
    elif parsed_args.picked_cmd == 'visualize':
        return visualizing_cli.process_arguments(parsed_args)
    elif parsed_args.picked_cmd == 'analysis':
        return analysis_cli.process_arguments(parsed_args)

    return 64  # /usr/include/sysexits.h


if __name__ == '__main__':
    sys.exit(main())
