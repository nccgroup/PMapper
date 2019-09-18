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
import os
import os.path
from pathlib import Path
import sys
from typing import Optional

import botocore.session

from principalmapper.analysis.find_risks import gen_findings_and_print
import principalmapper.graphing.graph_actions
from principalmapper.graphing.edge_identification import checker_map
from principalmapper.querying import query_actions
from principalmapper.querying import repl
from principalmapper.util import botocore_tools
from principalmapper.util.debug_print import dprint
from principalmapper.util.storage import get_storage_root
from principalmapper.visualizing import graph_writer


def main() -> int:
    """Point of entry for command-line"""
    argument_parser = argparse.ArgumentParser(prog='pmapper')
    argument_parser.add_argument(
        '--profile',
        help='AWS CLI (botocore) profile to use to call the AWS API'
    )  # Note: do NOT set the default, we want to know if the profile arg was specified or not
    argument_parser.add_argument(
        '--debug',
        action='store_true',
        help='Produces debug-level output'
    )
    argument_parser.add_argument(
        '--account',
        help='When running offline operations, this parameter determines which account to act against.'
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
    command_group = graphparser.add_mutually_exclusive_group(required=True)
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

    # Query subcommand
    queryparser = subparser.add_parser(
        'query',
        description='Displays information corresponding to a roughly human-readable query.',
        help='Displays information corresponding to a query'
    )
    queryparser.add_argument(
        '-s',
        '--skip-admin',
        action='store_true',
        help='Ignores "admin" level principals when querying about multiple principals in an account'
    )
    queryparser.add_argument(
        'query',
        help='The query to execute.'
    )

    # New Query subcommand
    argqueryparser = subparser.add_parser(
        'argquery',
        description='Displays information corresponding to a arg-specified query.',
        help='Displays information corresponding to a query'
    )
    argqueryparser.add_argument(
        '-s',
        '--skip-admin',
        action='store_true',
        help='Ignores administrative principals when querying about multiple principals in an account'
    )
    argqueryparser.add_argument(
        '--principal',
        default='*',
        help='A string matching one or more IAM users or roles in the account, or use * (the default) to include all'
    )
    argqueryparser.add_argument(
        '--action',
        help='An AWS action to test for, allows * wildcards'
    )
    argqueryparser.add_argument(
        '--resource',
        default='*',
        help='An AWS resource (denoted by ARN) to test for'
    )
    argqueryparser.add_argument(
        '--condition',
        action='append',
        help='A set of key-value pairs to test specific conditions'
    )
    argqueryparser.add_argument(
        '--preset',
        help='A preset query to run'
    )

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
    visualizationparser.add_argument(
        '--filetype',
        default='svg',
        choices=['svg', 'png', 'dot'],
        help='The (lowercase) filetype to output the image as.'
    )

    # Analysis subcommand
    analysisparser = subparser.add_parser(
        'analysis',
        description='Analyzes and reports identified issues',
        help='Analyzes and reports identified issues'
    )
    analysisparser.add_argument(
        '--output-type',
        default='text',
        choices=['text', 'json'],
        help='The type of output for identified issues.'
    )

    # TODO: Cross-Account subcommand(s)

    parsed_args = argument_parser.parse_args()

    dprint(parsed_args.debug, 'Debugging mode enabled.')
    dprint(parsed_args.debug, 'Parsed Args: ' + str(parsed_args))

    if parsed_args.picked_cmd == 'graph':
        return handle_graph(parsed_args)
    elif parsed_args.picked_cmd == 'query':
        return handle_query(parsed_args)
    elif parsed_args.picked_cmd == 'argquery':
        return handle_argquery(parsed_args)
    elif parsed_args.picked_cmd == 'repl':
        return handle_repl(parsed_args)
    elif parsed_args.picked_cmd == 'visualize':
        return handle_visualization(parsed_args)
    elif parsed_args.picked_cmd == 'analysis':
        return handle_analysis(parsed_args)

    return 64  # /usr/include/sysexits.h


def handle_graph(parsed_args) -> int:
    """Processes the arguments for the graph subcommand and executes related tasks"""
    session = _grab_session(parsed_args)

    if parsed_args.create:  # --create
        graph = principalmapper.graphing.graph_actions.create_new_graph(session, checker_map.keys(), parsed_args.debug)
        principalmapper.graphing.graph_actions.print_graph_data(graph)
        graph.store_graph_as_json(os.path.join(get_storage_root(), graph.metadata['account_id']))

    elif parsed_args.display:  # --display
        graph = principalmapper.graphing.graph_actions.get_existing_graph(
            session,
            parsed_args.account,
            parsed_args.debug
        )
        principalmapper.graphing.graph_actions.print_graph_data(graph)

    elif parsed_args.list:  # --list
        print("Account IDs:")
        print("---")
        storage_root = Path(get_storage_root())
        for direct in storage_root.iterdir():
            print(direct.name)

    elif parsed_args.update_edges:  # --update-edges
        graph = principalmapper.graphing.graph_actions.get_existing_graph(
            session,
            parsed_args.account,
            parsed_args.debug
        )
        graph.edges = principalmapper.graphing.edge_identification.obtain_edges(session, checker_map.keys(),
                                                                                graph.nodes, sys.stdout,
                                                                                parsed_args.debug)
        principalmapper.graphing.graph_actions.print_graph_data(graph)
        graph.store_graph_as_json(os.path.join(get_storage_root(), graph.metadata['account_id']))

    return 0


def handle_query(parsed_args) -> int:
    """Processes the arguments for the query subcommand and executes related tasks"""
    session = _grab_session(parsed_args)
    graph = principalmapper.graphing.graph_actions.get_existing_graph(session, parsed_args.account, parsed_args.debug)

    query_actions.query_response(graph, parsed_args.query, parsed_args.skip_admin, sys.stdout, parsed_args.debug)

    return 0


def handle_argquery(parsed_args) -> int:
    """Processes the arguments for the argquery subcommand and executes related tasks"""
    session = _grab_session(parsed_args)
    graph = principalmapper.graphing.graph_actions.get_existing_graph(session, parsed_args.account, parsed_args.debug)

    # process condition args to generate input dict
    conditions = {}
    if parsed_args.condition is not None:
        for arg in parsed_args.condition:
            # split on equals-sign (=), assume first instance separates the key and value
            components = arg.split('=')
            if len(components) < 2:
                print('Format for condition args not matched: <key>=<value>')
                return 64
            key = components[0]
            value = '='.join(components[1:])
            conditions.update({key: value})

    query_actions.argquery(graph, parsed_args.principal, parsed_args.action, parsed_args.resource, conditions,
                           parsed_args.preset, parsed_args.skip_admin, sys.stdout, parsed_args.debug)

    return 0


def handle_repl(parsed_args):
    """Processes the arguments for the query REPL and initiates"""
    session = _grab_session(parsed_args)
    graph = principalmapper.graphing.graph_actions.get_existing_graph(session, parsed_args.account, parsed_args.debug)

    repl_obj = repl.PMapperREPL(graph)
    repl_obj.begin_repl()

    return 0


def handle_visualization(parsed_args):
    """Processes the arguments for the visualization subcommand and executes related tasks"""
    # get Graph to draw/write
    session = _grab_session(parsed_args)
    graph = principalmapper.graphing.graph_actions.get_existing_graph(session, parsed_args.account, parsed_args.debug)

    # create file
    filepath = './{}.{}'.format(graph.metadata['account_id'], parsed_args.filetype)
    graph_writer.handle_request(graph, filepath, parsed_args.filetype)

    return 0


def handle_analysis(parsed_args):
    """Processes the arguments for the analysis subcommand and executes related tasks"""
    # get Graph object
    session = _grab_session(parsed_args)
    graph = principalmapper.graphing.graph_actions.get_existing_graph(session, parsed_args.account, parsed_args.debug)

    # execute analysis
    gen_findings_and_print(graph, parsed_args.output_type)

    return 0


def _grab_session(parsed_args) -> Optional[botocore.session.Session]:
    if parsed_args.account is None:
        return botocore_tools.get_session(parsed_args.profile)
    else:
        return None


if __name__ == '__main__':
    sys.exit(main())
