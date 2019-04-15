"""A collection of functions to create a DOT file to be rendered."""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import botocore.session
import pydot
import sys

from .awsgraph import AWSGraph
from .queries.util import *
from .queries.privesc import PrivEscQuery


def perform_visualization(parsed, account, session, graph):
    """Creates output.(dot|svg) files in the current directory for a given graph."""

    iamclient = session.create_client('iam')
    pydot_node_dict = {}
    dot_graph = pydot.Dot(graph_type='digraph', overlap='scale', layout='neato', concentrate='true', splines='true')
    admins = []
    for node in graph.nodes:
        n_e_tuples = get_relevant_nodes(graph, node)
        result = PrivEscQuery.run_query(iamclient, graph, node, n_e_tuples)
        color = 'white'
        if result[0] == 2:  # use other principal to priv-esc
            color = '#FADBD8'
        elif result[0] == 1:  # already admin
            color = '#BFEFFF'
            admins.append(node)
        pydot_node_dict[node] = pydot.Node(str(node), style='filled', fillcolor=color, shape='box')
        dot_graph.add_node(pydot_node_dict[node])
    for edge in graph.edges:
        if edge.nodeX not in admins:
            dot_graph.add_edge(pydot.Edge(pydot_node_dict[edge.nodeX], pydot_node_dict[edge.nodeY]))

    filepath = ''
    if parsed.profile is not None:
        filepath = 'pmapper-viz-' + parsed.profile
    else:
        filepath = 'pmapper-viz-acct-' + account
    graphfile = open(filepath + '.dot', 'w')
    graphfile.write(dot_graph.to_string())
    graphfile.close()
    dot_graph.write_svg(filepath + '.svg')
    print('Wrote SVG file ' + filepath + '.svg')
