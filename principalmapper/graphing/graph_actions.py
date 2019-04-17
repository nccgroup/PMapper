"""Code for creating graphs for Principal Mapper"""

import sys

import botocore.session
import principalmapper
from principalmapper.common.graphs import Graph
from principalmapper.graphing import gathering
from principalmapper.util.debug_print import dprint
from typing import Optional


def print_graph_data(graph: Graph) -> None:
    """Given a Graph object, print information about the Graph"""
    print('Graph Data for Account:  {}'.format(graph.metadata['account_id']))
    print('# of Nodes:              {}'.format(len(graph.nodes)))
    print('# of Edges:              {}'.format(len(graph.edges)))
    print('# of Groups:             {}'.format(len(graph.groups)))
    print('# of (tracked) Policies: {}'.format(len(graph.policies)))


def create_new_graph(session: botocore.session.Session, debug=False) -> Graph:
    """Implements creating a graph from AWS API data and returning the resulting Graph object"""
    stsclient = session.create_client('sts')
    caller_identity = stsclient.get_caller_identity()
    dprint(debug, "Caller Identity: {}".format(caller_identity['Arn']))
    metadata = {'account_id': caller_identity['Account'], 'pmapper_version': principalmapper.__version__}
    return gathering.create_graph(session, metadata, sys.stdout, debug)


def get_graph_from_disk(account: str) -> Graph:
    """Returns a Graph object constructed from data stored on-disk"""
    return Graph.create_graph_from_local_disk(account_id=account)


def get_existing_graph(session: Optional[botocore.session.Session], account: Optional[str], debug=False) -> Graph:
    """Implements creating a graph from data stored on disk and returning the resulting Graph object"""
    if account is not None:
        dprint(debug, 'Loading account data based on parameter --account')
        graph = get_graph_from_disk(account)
    elif session is not None:
        dprint(debug, 'Loading account data using a botocore session object')
        stsclient = session.create_client('sts')
        response = stsclient.get_caller_identity()
        graph = get_graph_from_disk(response['Account'])
    else:
        raise ValueError('One of parameters account or session must not be None')
    return graph

