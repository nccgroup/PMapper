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
                    result.append(
                        search_authorization_for(graph, node, action_param, resource_param, condition_param, debug))
            else:
                result.append(
                    search_authorization_for(graph, node, action_param, resource_param, condition_param, debug))

    else:
        node = graph.get_node_by_searchable_name(principal_param)
        if skip_admins:
            if not node.is_admin:
                result.append(
                    search_authorization_for(graph, node, action_param, resource_param, condition_param, debug))
        else:
            result.append(search_authorization_for(graph, node, action_param, resource_param, condition_param, debug))

    for query_result in result:
        query_result.write_result(action_param, resource_param, output)
