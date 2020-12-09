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

import json
import logging
import os
from argparse import ArgumentParser, Namespace
from pathlib import Path

from principalmapper.graphing import graph_actions
from principalmapper.graphing.edge_identification import checker_map
from principalmapper.util import botocore_tools
from principalmapper.util.storage import get_storage_root


logger = logging.getLogger(__name__)


def provide_arguments(parser: ArgumentParser):
    """Given a parser object (which should be a subparser), add arguments to provide a CLI interface to the
    graphing component of Principal Mapper.
    """

    graph_subparser = parser.add_subparsers(
        title='graph_subcommand',
        description='The subcommand to use in the graphing component of Principal Mapper',
        dest='picked_graph_cmd',
        help='Select a graph-subcommand to execute'
    )

    # args for commands fitting the pattern "pmapper graph create ..."
    create_parser = graph_subparser.add_parser(
        'create',
        description='Creates a Graph object for a given AWS account',
        help='Creates a Graph object for a given AWS account'
    )
    region_args_group = create_parser.add_mutually_exclusive_group()
    region_args_group.add_argument(
        '--include-regions',
        nargs='*',
        help='An allow-list of regions to pull data from, cannot be combined with --exclude-regions, the `global` region is always included',
        metavar='REGION'
    )
    region_args_group.add_argument(
        '--exclude-regions',
        nargs='*',
        help='A deny-list of regions to pull data from, cannot be combined with --include-regions, the `global` region is always included',
        metavar='REGION'
    )

    service_args_group = create_parser.add_mutually_exclusive_group()
    service_args_group.add_argument(
        '--include-services',
        nargs='*',
        help='An allow-list of services to search for Edge objects, cannot be combined with --exclude-services',
        metavar='SERVICE'
    )
    service_args_group.add_argument(
        '--exclude-services',
        nargs='*',
        help='A deny-list of services to search for Edge objects, cannot be combined with --include-services',
        metavar='SERVICE'
    )

    # args for commands fitting the pattern "pmapper graph display ..."
    display_parser = graph_subparser.add_parser(
        'display',
        description='Displays information about a Graph object for a given AWS account',
        help='Displays information about a Graph object for a given AWS account'
    )

    # args for commands fitting the pattern "pmapper graph list ..."
    list_parser = graph_subparser.add_parser(
        'list',
        description='List the Account IDs of graphs stored on this computer',
        help='List the Account IDs of graphs stored on this computer'
    )


def process_arguments(parsed_args: Namespace):
    """Given a namespace object generated from parsing args, perform the appropriate tasks. Returns an int
    matching expectations set by /usr/include/sysexits.h for command-line utilities."""

    if parsed_args.picked_graph_cmd == 'create':
        logger.debug('Called create subcommand of graph')

        # filter the args first
        if parsed_args.account is not None:
            print('Cannot specify offline-mode param `--account` when calling `pmapper graph create`. If you have '
                  'credentials for a specific account to graph, you can use those credentials similar to how the '
                  'AWS CLI works (environment variables, profiles, EC2 instance metadata). In the case of using '
                  'a profile, use the `--profile [PROFILE]` argument before specifying the `graph` subcommand.')
            return 64

        service_list_base = list(checker_map.keys())
        if parsed_args.include_services is not None:
            service_list = [x for x in service_list_base if x in parsed_args.include_services]
        elif parsed_args.exclude_services is not None:
            service_list = [x for x in service_list_base if x not in parsed_args.exclude_services]
        else:
            service_list = service_list_base
        logger.debug('Service list after processing args: {}'.format(service_list))

        session = botocore_tools.get_session(parsed_args.profile)
        graph = graph_actions.create_new_graph(session, service_list, parsed_args.include_regions, parsed_args.exclude_regions)
        graph_actions.print_graph_data(graph)
        graph.store_graph_as_json(os.path.join(get_storage_root(), graph.metadata['account_id']))

    elif parsed_args.picked_graph_cmd == 'display':
        if parsed_args.account is None:
            session = botocore_tools.get_session(parsed_args.profile)
        else:
            session = None

        graph = graph_actions.get_existing_graph(
            session,
            parsed_args.account
        )
        graph_actions.print_graph_data(graph)

    elif parsed_args.picked_graph_cmd == 'list':
        print("Account IDs:")
        print("---")
        storage_root = Path(get_storage_root())
        for direct in storage_root.iterdir():
            metadata_file = direct.joinpath(Path('metadata.json'))
            with open(str(metadata_file)) as fd:
                version = json.load(fd)['pmapper_version']
            print("{} (PMapper Graph Version {})".format(direct.name, version))

    return 0
