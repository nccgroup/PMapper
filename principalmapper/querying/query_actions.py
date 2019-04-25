"""Code for executing queries given by the Principal Mapper command-line"""

import io
import os
from typing import Optional

import botocore.session

from principalmapper.common.graphs import Graph
from principalmapper.querying.query_interface import search_authorization_for


def argquery_response(session: botocore.session.Session, graph: Graph, principal_param: Optional[str],
                      action_param: str, resource_param: Optional[str], condition_param: Optional[dict],
                      skip_admins: bool = False, output: io.StringIO = os.devnull, debug: bool = False) -> None:
    """Writes the output of a query to output."""
    if session is not None:
        iamclient = session.create_client('iam')
    else:
        iamclient = None

    result = []

    if resource_param is None:
        resource_param = '*'

    if principal_param is None or principal_param == '*':
        for node in graph.nodes:
            if skip_admins:
                if not node.is_admin:
                    result.append(search_authorization_for(iamclient, graph, node, action_param, resource_param,
                                                           condition_param, iamclient is not None, debug))
            else:
                result.append(search_authorization_for(iamclient, graph, node, action_param, resource_param,
                                                       condition_param, iamclient is not None, debug))

    else:
        node = graph.get_node_by_searchable_name(principal_param)
        if skip_admins:
            if not node.is_admin:
                result.append(search_authorization_for(iamclient, graph, node, action_param, resource_param,
                                                       condition_param, iamclient is not None, debug))
        else:
            result.append(search_authorization_for(iamclient, graph, node, action_param, resource_param,
                                                   condition_param, iamclient is not None, debug))

    for query_result in result:
        if query_result.allowed:
            if len(query_result.edge_list) == 0:
                # node itself is auth'd
                output.write('{} is authorized to call action {} for resource {}\n'.format(
                    query_result.node.searchable_name(), action_param, resource_param))

            else:
                # node has to go through the edge list
                output.write('{} is authorized to call action {} for resource {} via {}:'.format(
                    query_result.node.searchable_name(), action_param, resource_param,
                    query_result.edge_list[-1].destination
                ))
                for edge in query_result.edge_list:
                    output.write('   {}'.format(edge.describe_edge()))
