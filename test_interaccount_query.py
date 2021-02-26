#!/usr/bin/env python

"""Brief test, hopefully I don't make a mistake and commit this..."""

from principalmapper.common import *
from principalmapper.util.storage import get_storage_root
from principalmapper.util import arns
import os
import os.path
from principalmapper.querying.query_orgs import produce_scp_list
from principalmapper.graphing.cross_account_edges import get_edges_between_graphs
from principalmapper.querying import query_utils, query_interface

graphs = [
	Graph.create_graph_from_local_disk(os.path.join(get_storage_root(), '670903390496')),
	Graph.create_graph_from_local_disk(os.path.join(get_storage_root(), '034528927469'))
]
inter_edges = get_edges_between_graphs(graphs[0], graphs[1])
org_tree = OrganizationTree.create_from_dir(os.path.join(get_storage_root(), 'o-zo89o5n1ru'))

print('Loaded accounts 670903390496 and 034528927469 and derived edges')

graph_scp_pairs = []
for graph in graphs:
	graph_scp_pairs.append(
		(graph, produce_scp_list(graph, org_tree))
	)

calling_node = graphs[0].get_node_by_searchable_name('user/LambdaFullAccess')
target_node = graphs[1].get_node_by_searchable_name('role/OrganizationAccountAccessRole')

query_result = query_interface.search_authorization_across_accounts(graph_scp_pairs, inter_edges, calling_node, 'sts:AssumeRole', target_node.arn, {}, target_node.trust_policy, '034528927469')
query_result.print_result('sts:AssumeRole', target_node.arn)



