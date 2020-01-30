"""Utility functions that help with querying"""

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

import json
from typing import List, Optional
import re

import botocore.session

from principalmapper.common import Edge, Graph, Node, Policy
from principalmapper.util import arns


def get_search_list(graph: Graph, node: Node) -> List[List[Edge]]:
    """Returns a list of edge lists. Each edge list represents a path to a new unique node that's accessible from the
    initial node (passed as a param). This is a breadth-first search of nodes from a source node in a graph.
    """
    result = []
    explored_nodes = []

    # Special-case: node is an "admin", so we make up admin edges and return them all
    if node.is_admin:
        for other_node in graph.nodes:
            if node == other_node:
                continue
            result.append([Edge(node, other_node, 'can access through administrative actions', 'Admin')])
        return result

    # run through initial edges
    for edge in get_edges_with_node_source(graph, node, explored_nodes):
        result.append([edge])
    explored_nodes.append(node)

    # dig through result list
    index = 0
    while index < len(result):
        current_node = result[index][-1].destination
        for edge in get_edges_with_node_source(graph, current_node, explored_nodes):
            result.append(result[index][:] + [edge])
        explored_nodes.append(current_node)
        index += 1

    return result


def get_edges_with_node_source(graph: Graph, node: Node, ignored_nodes: List[Node]) -> List[Edge]:
    """Returns a list of nodes that are the destination of edges from the given graph where source of the edge is the
    passed node.
    """
    result = []
    for edge in graph.edges:
        if edge.source == node and edge.destination not in ignored_nodes:
            result.append(edge)
    return result


def is_connected(graph: Graph, source: Node, destination: Node) -> bool:
    """helper function to express if source and node are connected"""
    if source.is_admin:
        return True

    for node_list in get_search_list(graph, source):
        if node_list[-1].destination == destination:
            return True

    return False


def pull_cached_resource_policy_by_arn(policies: List[Policy], arn: Optional[str], query: str = None) -> dict:
    """Function that pulls a resource policy that's cached on-disk.

    Raises ValueError if it is not able to be retrieved.
    Returns the dict, not the Policy object.
    """
    if query is not None:
        if arn is not None:
            raise ValueError('Must specify either arn or query, not both.')
        pattern = re.compile(r'.*(arn:[^:]*:[^:]*:[^:]*:[^:]*:\S+).*')
        matches = pattern.match(query)
        if matches is None:
            raise ValueError('Resource policy retrieval error: could not extract resource ARN from query')
        arn = matches.group(1)
    if '?' in arn or '*' in arn:
        raise ValueError('Resource component from query must not have wildcard (? or *) when evaluating '
                         'resource policies.')

    # manipulate the ARN as needed
    service = arns.get_service(arn)
    if service == 's3':
        # we only need the ARN of the bucket
        search_arn = 'arn:{}:s3:::{}'.format(arns.get_partition(arn), arns.get_resource(arn).split('/')[0])
    elif service == 'iam':
        search_arn = arn
    elif service == 'sns':
        search_arn = arn
    elif service == 'sqs':
        search_arn = arn
    elif service == 'kms':
        search_arn = arn
    else:
        raise NotImplementedError('Service policies for {} are not cached.'.format(service))

    for policy in policies:
        if search_arn == policy.arn:
            return policy.policy_doc

    raise ValueError('Unable to locate a cached policy for resource {}'.format(arn))


def pull_resource_policy_by_arn(session: botocore.session.Session, arn: Optional[str], query: str = None) -> dict:
    """helper function for pulling the resource policy for a resource at the denoted ARN.

    raises ValueError if it cannot be retrieved.
    """
    if query is not None:
        if arn is not None:
            raise ValueError('Must specify either arn or query, not both.')
        pattern = re.compile(r'.*(arn:[^:]*:[^:]*:[^:]*:[^:]*:\S+).*')
        matches = pattern.match(query)
        if matches is None:
            raise ValueError('Resource policy retrieval error: could not extract resource ARN from query')
        arn = matches.group(1)
        if '?' in arn or '*' in arn:
            raise ValueError('Resource component from query must not have wildcard (? or *) when evaluating '
                             'resource policies.')

    service = arns.get_service(arn)
    if service == 'iam':
        # arn:aws:iam::<account_id>:role/<role_name>
        client = session.create_client('iam')
        role_name = arns.get_resource(arn).split('/')[-1]
        trust_doc = client.get_role(RoleName=role_name)['Role']['AssumeRolePolicyDocument']
        return trust_doc
    elif service == 's3':
        # arn:aws:s3:::<bucket>/<path_to_object_with_potential_colons>
        client = session.create_client('s3')
        bucket_name = arns.get_resource(arn).split('arn:aws:s3:::')[-1].split('/')[0]
        bucket_policy = json.loads(client.get_bucket_policy(Bucket=bucket_name)['Policy'])
        return bucket_policy
    elif service == 'sns':
        region = arns.get_region(arn)
        client = session.create_client('sns', region_name=region)
        # policy = ...
        raise NotImplementedError('Need to implement topic policy grabbing')
    elif service == 'sqs':
        region = arns.get_region(arn)
        client = session.create_client('sqs', region_name=region)
        # policy = ...
        raise NotImplementedError('Need to implement queue policy grabbing')
    elif service == 'kms':
        region = arns.get_region(arn)
        client = session.create_client('kms', region_name=region)
        # policy = ...
        raise NotImplementedError('Need to implement KMS key policy grabbing')
