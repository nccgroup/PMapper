"""Code for executing commands given by the Principal Mapper command-line"""

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
import os
import os.path
import sys

import botocore.session
from principalmapper.common import Graph
from principalmapper.graphing import gathering
from principalmapper.util.storage import get_default_graph_path
from typing import List, Optional


logger = logging.getLogger(__name__)


def create_new_graph(session: botocore.session.Session, service_list: List[str],
                     region_allow_list: Optional[List[str]] = None, region_deny_list: Optional[List[str]] = None,
                     scps: Optional[List[List[dict]]] = None, client_args_map: Optional[dict] = None) -> Graph:
    """Wraps around principalmapper.graphing.gathering.create_graph(...) This fulfills `pmapper graph create`.
    """

    return gathering.create_graph(session, service_list, region_allow_list, region_deny_list, scps, client_args_map)


def print_graph_data(graph: Graph) -> None:
    """Given a Graph object, prints a small amount of information about the Graph. This fulfills
    `pmapper graph display`, and also gets ran after `pmapper graph --create`.
    """
    print('Graph Data for Account:  {}'.format(graph.metadata['account_id']))
    if 'org-id' in graph.metadata:
        print('  Organization: {}'.format(graph.metadata['org-id']))
        print('  OU Path:      {}'.format(graph.metadata['org-path']))
    admin_count = 0
    for node in graph.nodes:
        if node.is_admin:
            admin_count += 1
    print('  # of Nodes:              {} ({} admins)'.format(len(graph.nodes), admin_count))
    print('  # of Edges:              {}'.format(len(graph.edges)))
    print('  # of Groups:             {}'.format(len(graph.groups)))
    print('  # of (tracked) Policies: {}'.format(len(graph.policies)))


def get_graph_from_disk(location: str) -> Graph:
    """Returns a Graph object constructed from data stored on-disk at any location. This basically wraps around the
    static method in principalmapper.common.graph named Graph.create_graph_from_local_disk(...).
    """

    return Graph.create_graph_from_local_disk(location)


def get_existing_graph(session: Optional[botocore.session.Session], account: Optional[str]) -> Graph:
    """Returns a Graph object stored on-disk in a standard location (per-OS, using the get_storage_root utility function
    in principalmapper.util.storage). Uses the session/account parameter to choose the directory from under the
    standard location.
    """
    if account is not None:
        logger.debug('Loading graph based on given account id: {}'.format(account))
        graph = get_graph_from_disk(get_default_graph_path(account))
    elif session is not None:
        stsclient = session.create_client('sts')
        response = stsclient.get_caller_identity()
        logger.debug('Loading graph based on sts:GetCallerIdentity result: {}'.format(response['Account']))
        graph = get_graph_from_disk(os.path.join(get_default_graph_path(response['Account'])))
    else:
        raise ValueError('One of the parameters `account` or `session` must not be None')
    return graph

