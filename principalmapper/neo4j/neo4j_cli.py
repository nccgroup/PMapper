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

from principalmapper.common import OrganizationTree, OrganizationNode, Graph, OrganizationAccount, Policy, Edge
from principalmapper.graphing.cross_account_edges import get_edges_between_graphs
from principalmapper.graphing.gathering import get_organizations_data
from principalmapper.querying.query_orgs import produce_scp_list
from principalmapper.util import botocore_tools
from principalmapper.graphing import graph_actions
from principalmapper.util.storage import get_storage_root
from principalmapper.neo4j.neo4j_driver import load_graph_to_neo4j, load_cross_account_edges_to_neo4j, load_external_edges_to_neo4j, load_identitycentre_to_neo4j

from principalmapper.querying.presets import externalaccess
from principalmapper.util.arns import get_resource, validate_arn, get_account_id, is_valid_aws_account_id


logger = logging.getLogger(__name__)


def provide_arguments(parser: ArgumentParser):
    """Given a parser object (which should be a subparser), add arguments to provide a CLI interface to the
    organizations component of Principal Mapper.
    """

    neo4j_subparser = parser.add_subparsers(
        title='neo4j_subcommand',
        description='The subcommand to use in the neo4j component of Principal Mapper',
        dest='picked_neo4j_cmd',
        help='Select neo4j subcommand to execute'
    )

    load_parser = neo4j_subparser.add_parser(
        'load',
        description='Loads all graphed accounts within the AWS Organizations into neo4j (inculdes cross-account, external access, and Identity Center info)',
        help='Loads all graphed accounts within AWS Organizations data into neo4j (inculdes cross-account, external access, and Identity Center info)',
    )
    load_parser.add_argument(
        '--org',
        help='The ID of the organization to update'
    )

    add_cross_account_access_parser = neo4j_subparser.add_parser(
        'add_cross_account_access',
        description='Updates the data stored in neo4j',
        help='Adds cross_account edges to the data stored in neo4j',
    )
    add_cross_account_access_parser.add_argument(
        '--org',
        help='The ID of the organization to update'
    )

    identitycentre_parser = neo4j_subparser.add_parser(
        'identitycenter',
        description='Updates the data stored in neo4j',
        help='Adds Identity Store data to neo4j',
    )
    identitycentre_parser.add_argument(
        '--org',
        help='The ID of the organization to update'
    )

    external_access_parser = neo4j_subparser.add_parser(
        'external_access',
        description='Updates the data stored in neo4j',
        help='Adds external accounts as nodes, and edges to these nodes, in neo4j',
    )
    external_access_parser.add_argument(
        '--org',
        help='The ID of the organization to update'
    )


def process_arguments(parsed_args: Namespace):
    """Given a namespace object generated from parsing args, perform the appropriate tasks. Returns an int
    matching expectations set by /usr/include/sysexits.h for command-line utilities."""


    # new args for handling AWS Organizations
    if parsed_args.picked_neo4j_cmd == 'load':
        logger.debug('Called load subcommand for neo4j')

        # filter the args first
        if parsed_args.account is None and parsed_args.org is None:
            print('Please specify either an account ID or and Org ID whose data should be updated in Neo4j')
            return 64
        
        if parsed_args.account and parsed_args.org:
            print('Please specify either an account ID or and Org ID whose data should be updated in Neo4j, not both.')
            return 64
        
        graph_objs = []
        
        if parsed_args.org:
            # pull the existing data from disk
            org_filepath = os.path.join(get_storage_root(), parsed_args.org)
            org_tree = OrganizationTree.create_from_dir(org_filepath)
        
            for account in org_tree.accounts:
                graph_objs.append(graph_actions.get_existing_graph(session=None,account=account))
        else:
            graph_objs.append(graph_actions.get_existing_graph(session=None,account=parsed_args.account))

        if not graph_objs:
            print('No graphs were loaded. Please check that the account data has already been ingested before running this command')
            return 64

        for graph_obj in graph_objs:
            # Load the data into Neo4j
            if not graph_obj:
                continue
            load_graph_to_neo4j(graph_obj)

        if parsed_args.org:
            if org_tree.edge_list:
                load_cross_account_edges_to_neo4j(org_tree.edge_list)

                external_edges,external_accounts = _generate_external_edges(graph_objs, org_tree)
                load_external_edges_to_neo4j(external_edges,external_accounts)

            if org_tree.identity_stores:
                load_identitycentre_to_neo4j(org_tree)
        else:
            # Load external edges for the single account
            external_edges,external_accounts = _generate_external_edges(graph_objs)
            load_external_edges_to_neo4j(external_edges,external_accounts)


    elif parsed_args.picked_neo4j_cmd == 'add_cross_account_access':
        logger.debug('Called add_cross_account_access subcommand for neo4j')

        # filter the args first
        if parsed_args.org is None:
            print('Please specify an Org ID for which cross account access should be loaded into Neo4j')
            return 64
        
        # pull the existing data from disk
        org_filepath = os.path.join(get_storage_root(), parsed_args.org)
        org_tree = OrganizationTree.create_from_dir(org_filepath)
        
        if org_tree.edge_list:
            load_cross_account_edges_to_neo4j(org_tree.edge_list)


    elif parsed_args.picked_neo4j_cmd == 'identitycentre':
        logger.debug('Called identitycentre subcommand for neo4j')

        # filter the args first
        if parsed_args.org is None:
            print('Please specify an Org ID for which cross account access should be loaded into Neo4j')
            return 64
        
        # pull the existing data from disk
        org_filepath = os.path.join(get_storage_root(), parsed_args.org)
        org_tree = OrganizationTree.create_from_dir(org_filepath)
        
        if org_tree.identity_stores:
            load_identitycentre_to_neo4j(org_tree)
        else:
            logger.warning("[!] No identity_store.json file found. Please run 'pmapper --profile {AWS Account ID} identitycentre --org {Organisation ID}'.")

    elif parsed_args.picked_neo4j_cmd == 'external_access':
        logger.debug('Called externalaccess subcommand for neo4j')

        # filter the args first
        if parsed_args.org is None:
            print('Please specify an Org ID for which cross account access should be loaded into Neo4j')
            return 64

        external_edges,external_accounts = _generate_external_edges(parsed_args)
        load_external_edges_to_neo4j(external_edges,external_accounts)
            
        
def _generate_external_edges(graph_objs, org_tree=None):
    # Get a unique list of external accounts
    external_accounts = set()
    # Get a list of external edges
    external_edges = []
    for graph_obj in graph_objs:
        external_access_nodes = externalaccess.determine_external_access(graph_obj, include_fedenerated = False)
        
        for node in external_access_nodes:
            for principal in node.allowed_external_access:
                if is_valid_aws_account_id(principal):
                    # Got an account ID
                    account_id = principal
                elif validate_arn(principal):
                    # Got a user, role, or root of account. Extract the account id
                    account_id = get_account_id(principal)
                else:
                    pass # Check why we got here
                
                if org_tree:
                    # Check if the account id is within the Org
                    if account_id in org_tree.accounts:
                        continue
                else:
                    external_edges.append(Edge(
                        source=principal,
                        destination=node.arn,
                        reason='can call sts:AssumeRole to access',
                        short_reason='STS'
                    ))
                    external_accounts.add(account_id)
    return external_edges,external_accounts