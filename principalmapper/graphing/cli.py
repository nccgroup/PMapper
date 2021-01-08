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
import re
from argparse import ArgumentParser, Namespace
from pathlib import Path

from principalmapper.common import OrganizationTree, OrganizationNode, Graph
from principalmapper.graphing import graph_actions
from principalmapper.graphing.cross_account_edges import get_edges_between_graphs
from principalmapper.graphing.gathering import get_organizations_data
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
        description='List the Account IDs and Organization IDs of graphs and org trees stored on this computer',
        help='List the accounts and organizations stored on this computer'
    )

    # new args for handling AWS Organizations
    org_create_parser = graph_subparser.add_parser(
        'org_create',
        description='Creates a OrganizationTree object for a given AWS Organization',
        help='Creates a OrganizationTree object for a given AWS Organization'
    )

    org_update_parser = graph_subparser.add_parser(
        'org_update',
        description='Updates all graphed accounts with AWS Organizations data - offline operation',
        help='Updates all graphed accounts with AWS Organizations data - offline operation',
    )

    org_display_parser = graph_subparser.add_parser(
        'org_display',
        description='Gives details on a given AWS Organization',
        help='Gives details on a given AWS Organization'
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

    elif parsed_args.picked_graph_cmd == 'org_create':
        logger.debug('Called create subcommand for organizations')

        # filter the args first
        if parsed_args.account is not None:
            print('Cannot specify offline-mode param `--account` when calling `pmapper graph org_create`. If you have '
                  'credentials for a specific account to graph, you can use those credentials similar to how the '
                  'AWS CLI works (environment variables, profiles, EC2 instance metadata). In the case of using '
                  'a profile, use the `--profile [PROFILE]` argument before specifying the `graph` subcommand.')
            return 64

        # get the botocore session and go to work creating the OrganizationTree obj
        session = botocore_tools.get_session(parsed_args.profile)
        org_tree = get_organizations_data(session)
        logger.info('Generated initial organization data for {}'.format(org_tree.org_id))

        # create the account -> OU path map and apply to all accounts (same as org_update operation)
        account_ou_map = _map_account_ou_paths(org_tree)
        logger.debug('account_ou_map: {}'.format(account_ou_map))
        _update_accounts_with_ou_path_map(org_tree.org_id, account_ou_map, get_storage_root())
        logger.info('Updated currently stored accounts with applicable AWS Organizations data')

        # create and cache a list of edges between all the accounts we have data for
        edge_list = []
        graph_objs = []
        for account in org_tree.accounts:
            try:
                potential_path = os.path.join(get_storage_root(), account)
                logger.debug('Trying to load a Graph from {}'.format(potential_path))
                graph_obj = Graph.create_graph_from_local_disk(potential_path)
                graph_objs.append(graph_obj)
            except Exception as ex:
                logger.warning('Unable to load a Graph object for account {}, possibly because it is not mapped yet. '
                               'Please map all accounts and then update the Organization Tree (`pmapper graph org_update`).')
                logger.debug(str(ex))

        for graph_obj_a in graph_objs:
            for graph_obj_b in graph_objs:
                if graph_obj_a == graph_obj_b:
                    continue
                edge_list.extend(get_edges_between_graphs(graph_obj_a, graph_obj_b))

        org_tree.edge_list = edge_list
        logger.info('Compiled cross-account edges')

        org_tree.save_organization_to_disk(os.path.join(get_storage_root(), org_tree.org_id))
        logger.info('Stored organization data to disk')

    elif parsed_args.picked_graph_cmd == 'org_display':
        raise NotImplementedError('TODO: org_create')

    elif parsed_args.picked_graph_cmd == 'org_update':
        raise NotImplementedError('TODO: org_update')

    return 0


def _map_account_ou_paths(org_tree: OrganizationTree) -> dict:
    """Given an OrganizationTree, create a map from account -> ou path"""
    result = {}

    def _traverse(org_node: OrganizationNode, base_string: str):
        full_node_str = '{}{}/'.format(base_string, org_node.ou_id)
        for account in org_node.accounts:
            result[account] = full_node_str
        for child_node in org_node.child_nodes:
            _traverse(child_node, full_node_str)

    for root_ou in org_tree.root_ous:
        _traverse(root_ou, '{}/'.format(org_tree.org_id))

    return result


def _update_accounts_with_ou_path_map(org_id: str, account_ou_map: dict, root_dir: str):
    """Given a map produced by `_map_account_ou_paths` go through the available on-disk graphs and update metadata
    appropriately."""

    for account, ou_path in account_ou_map.items():
        potential_path = os.path.join(root_dir, account.account_id, 'metadata.json')
        if os.path.exists(os.path.join(potential_path)):
            try:
                fd = open(potential_path, 'r')
                metadata = json.load(fd)
                new_org_data = {
                    'org-id': org_id,
                    'org-path': ou_path
                }
                logger.debug('Updating {} with org data: {}'.format(account.account_id, new_org_data))
                metadata['org-id'] = org_id
                metadata['org-path'] = ou_path
                fd.close()

                fd = open(potential_path, 'w')
                json.dump(metadata, fd, indent=4)
            except IOError as ex:
                logger.debug('IOError when reading/writing metadata of {}: {}'.format(account.account_id, str(ex)))
                continue
        else:
            logger.debug(
                'Account {} of organization {} does not have a Graph. You will need to update the '
                'organization data at a later point (`pmapper graph org_update`).'.format(account.account_id, org_id)
            )  # warning gets thrown up by caller, no need to reiterate
