"""Code to implement the CLI interface to the AWS Organizations (OrganizationTrees) component of Principal Mapper"""

#  Copyright (c) NCC Group and Erik Steringer 2021. This file is part of Principal Mapper.
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
import os.path
import re
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import List

from principalmapper.common import OrganizationTree, OrganizationNode, Graph, OrganizationAccount, Policy
from principalmapper.graphing.cross_account_edges import get_edges_between_graphs
from principalmapper.graphing.gathering import get_organizations_data
from principalmapper.querying.query_orgs import produce_scp_list
from principalmapper.util import botocore_tools
from principalmapper.util.storage import get_storage_root


logger = logging.getLogger(__name__)


def provide_arguments(parser: ArgumentParser):
    """Given a parser object (which should be a subparser), add arguments to provide a CLI interface to the
    organizations component of Principal Mapper.
    """

    orgs_subparser = parser.add_subparsers(
        title='orgs_subcommand',
        description='The subcommand to use in the organizations component of Principal Mapper',
        dest='picked_orgs_cmd',
        help='Select an organizations subcommand to execute'
    )

    create_parser = orgs_subparser.add_parser(
        'create',
        description='Creates and stores a OrganizationTree object for a given AWS Organization',
        help='Creates and stores a OrganizationTree object for a given AWS Organization'
    )

    list_parser = orgs_subparser.add_parser(
        'list',
        description='Lists the locally tracked AWS Organizations',
        help='Lists the locally tracked AWS Organizations'
    )

    update_parser = orgs_subparser.add_parser(
        'update',
        description='Updates all graphed accounts with AWS Organizations data - offline operation',
        help='Updates all graphed accounts with AWS Organizations data - offline operation',
    )
    update_parser.add_argument(
        '--org',
        help='The ID of the organization to update',
        required=True
    )

    display_parser = orgs_subparser.add_parser(
        'display',
        description='Gives details on a given AWS Organization',
        help='Gives details on a given AWS Organization'
    )
    display_parser.add_argument(
        '--org',
        help='The ID of the organization to display',
        required=True
    )


def process_arguments(parsed_args: Namespace):
    """Given a namespace object generated from parsing args, perform the appropriate tasks. Returns an int
    matching expectations set by /usr/include/sysexits.h for command-line utilities."""

    # new args for handling AWS Organizations
    if parsed_args.picked_orgs_cmd == 'create':
        logger.debug('Called create subcommand for organizations')

        # filter the args first
        if parsed_args.account is not None:
            print('Cannot specify offline-mode param `--account` when calling `pmapper orgs create`. If you have '
                  'credentials for a specific account to graph, you can use those credentials similar to how the '
                  'AWS CLI works (environment variables, profiles, EC2 instance metadata). In the case of using '
                  'a profile, use the `--profile [PROFILE]` argument before specifying the `orgs` subcommand.')
            return 64

        # get the botocore session and go to work creating the OrganizationTree obj
        session = botocore_tools.get_session(parsed_args.profile)
        org_tree = get_organizations_data(session)
        logger.info('Generated initial organization data for {}'.format(org_tree.org_id))

        # create the account -> OU path map and apply to all accounts (same as orgs update operation)
        account_ou_map = _map_account_ou_paths(org_tree)
        logger.debug('account_ou_map: {}'.format(account_ou_map))
        _update_accounts_with_ou_path_map(org_tree.org_id, account_ou_map, get_storage_root())
        logger.info('Updated currently stored Graphs with applicable AWS Organizations data')

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
                               'Please map all accounts and then update the Organization Tree '
                               '(`pmapper orgs update --org $ORG_ID`).'.format(account))
                logger.debug(str(ex))

        for graph_obj_a in graph_objs:
            for graph_obj_b in graph_objs:
                if graph_obj_a == graph_obj_b:
                    continue
                graph_a_scps = produce_scp_list(graph_obj_a, org_tree)
                graph_b_scps = produce_scp_list(graph_obj_b, org_tree)
                edge_list.extend(get_edges_between_graphs(graph_obj_a, graph_obj_b, graph_a_scps, graph_b_scps))

        org_tree.edge_list = edge_list
        logger.info('Compiled cross-account edges')

        org_tree.save_organization_to_disk(os.path.join(get_storage_root(), org_tree.org_id))
        logger.info('Stored organization data to disk')

    elif parsed_args.picked_orgs_cmd == 'update':
        # pull the existing data from disk
        org_filepath = os.path.join(get_storage_root(), parsed_args.org)
        org_tree = OrganizationTree.create_from_dir(org_filepath)

        # create the account -> OU path map and apply to all accounts
        account_ou_map = _map_account_ou_paths(org_tree)
        logger.debug('account_ou_map: {}'.format(account_ou_map))
        _update_accounts_with_ou_path_map(org_tree.org_id, account_ou_map, get_storage_root())
        logger.info('Updated currently stored Graphs with applicable AWS Organizations data')

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
                               'Please map all accounts and then update the Organization Tree '
                               '(`pmapper orgs update --org $ORG_ID`).'.format(account))
                logger.debug(str(ex))

        for graph_obj_a in graph_objs:
            for graph_obj_b in graph_objs:
                if graph_obj_a == graph_obj_b:
                    continue
                graph_a_scps = produce_scp_list(graph_obj_a, org_tree)
                graph_b_scps = produce_scp_list(graph_obj_b, org_tree)
                edge_list.extend(get_edges_between_graphs(graph_obj_a, graph_obj_b, graph_a_scps, graph_b_scps))

        org_tree.edge_list = edge_list
        logger.info('Compiled cross-account edges')

        org_tree.save_organization_to_disk(os.path.join(get_storage_root(), org_tree.org_id))
        logger.info('Stored organization data to disk')

    elif parsed_args.picked_orgs_cmd == 'display':
        # pull the existing data from disk
        org_filepath = os.path.join(get_storage_root(), parsed_args.org)
        org_tree = OrganizationTree.create_from_dir(org_filepath)

        def _print_account(org_account: OrganizationAccount, indent_level: int, inherited_scps: List[Policy]):
            print('{} {}:'.format(' ' * indent_level, org_account.account_id))
            print('{}  Directly Attached SCPs: {}'.format(' ' * indent_level, [x.name for x in org_account.scps]))
            print('{}  Inherited SCPs:         {}'.format(' ' * indent_level, [x.name for x in inherited_scps]))

        def _walk_and_print_ou(org_node: OrganizationNode, indent_level: int, inherited_scps: List[Policy]):
            print('{}"{}" ({}):'.format(' ' * indent_level, org_node.ou_name, org_node.ou_id))
            print('{}  Accounts:'.format(' ' * indent_level))
            for o_account in org_node.accounts:
                _print_account(o_account, indent_level + 2, inherited_scps)
            print('{}  Directly Attached SCPs: {}'.format(' ' * indent_level, [x.name for x in org_node.scps]))
            print('{}  Inherited SCPs:         {}'.format(' ' * indent_level, [x.name for x in inherited_scps]))
            print('{}  Child OUs:'.format(' ' * indent_level))
            for child_node in org_node.child_nodes:
                new_inherited_scps = inherited_scps.copy()
                new_inherited_scps.extend([x for x in org_node.scps if x not in inherited_scps])
                _walk_and_print_ou(child_node, indent_level + 4, new_inherited_scps)

        print('Organization {}:'.format(org_tree.org_id))
        for root_ou in org_tree.root_ous:
            _walk_and_print_ou(root_ou, 0, [])

    elif parsed_args.picked_orgs_cmd == 'list':
        print("Organization IDs:")
        print("---")
        storage_root = Path(get_storage_root())
        account_id_pattern = re.compile(r'o-\w+')
        for direct in storage_root.iterdir():
            if account_id_pattern.search(str(direct)) is not None:
                metadata_file = direct.joinpath(Path('metadata.json'))
                with open(str(metadata_file)) as fd:
                    version = json.load(fd)['pmapper_version']
                print("{} (PMapper Version {})".format(direct.name, version))

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
                'organization data at a later point (`pmapper orgs update --org $ORG_ID`).'.format(account.account_id, org_id)
            )  # warning gets thrown up by caller, no need to reiterate
