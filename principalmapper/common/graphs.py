"""Python module containing the Graph class and any Graph-specific utility functions (currently none)."""


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
import logging
import os
import os.path
from typing import Optional

import packaging
import packaging.version

import principalmapper
from principalmapper.common.edges import Edge
from principalmapper.common.groups import Group
from principalmapper.common.nodes import Node
from principalmapper.common.policies import Policy


logger = logging.getLogger(__name__)


class Graph(object):
    """The basic Graph object: contains nodes, edges, policies, and groups. Also includes code for saving and loading
    Graph data to/from files stored on-disk. The actual attributes of each graph/node/edge/policy/group object
    will remain the same across the same major+minor version of Principal Mapper, so a graph generated in v1.0.0
    should be loadable in v1.0.1, but not v1.1.0.

    * **v1.2.0:** Shifted account/partition to arguments of Graph construction
    """

    def __init__(self, nodes: list, edges: list, policies: list, groups: list, account: str, partition: str,
                 metadata: dict):
        """Constructor"""

        for x in (nodes, edges, policies, groups, account, partition, metadata):
            if x is None:
                raise ValueError(f'Required argument {x} was None')

        self.nodes = nodes
        self.edges = edges
        self.policies = policies
        self.groups = groups

        self.account = account
        if not isinstance(account, str):
            raise ValueError('Parameter `account` is expected to be str')

        self.partition = partition
        if not isinstance(partition, str):
            raise ValueError('Parameter `partition` is expected to be str')

        if not isinstance(metadata, dict):
            raise ValueError('Parameter `metadata` is expected to be dict')

        if 'pmapper_version' not in metadata:
            raise ValueError('Incomplete metadata input, expected key: "pmapper_version"')
        self.metadata = metadata

    def get_node_by_searchable_name(self, name: str) -> Optional[Node]:
        """Locates a node by a given searchable name, returns the Node or None"""
        for node in self.nodes:
            if node.searchable_name() == name:
                return node
        return None

    def store_graph_as_json(self, root_directory: str):
        """Stores the current Graph as a set of JSON documents on-disk in a standard layout.

        If the directory does not exist yet, it is created.

        Structure:
        | <root_directory parameter>
        |---- data.json
        |---- metadata.json
        |---- graph/
        |-------- nodes.json
        |-------- edges.json
        |-------- policies.json
        |-------- groups.json

        The client app (such as __main__.py of principalmapper) will specify where to retrieve the data.
        """
        rootpath = root_directory
        if not os.path.exists(rootpath):
            os.makedirs(rootpath, 0o700)
        graphdir = os.path.join(rootpath, 'graph')
        if not os.path.exists(graphdir):
            os.makedirs(graphdir, 0o700)
        regulardatafilepath = os.path.join(rootpath, 'data.json')
        metadatafilepath = os.path.join(rootpath, 'metadata.json')
        nodesfilepath = os.path.join(graphdir, 'nodes.json')
        edgesfilepath = os.path.join(graphdir, 'edges.json')
        policiesfilepath = os.path.join(graphdir, 'policies.json')
        groupsfilepath = os.path.join(graphdir, 'groups.json')

        old_umask = os.umask(0o077)  # block rwx for group/all
        with open(regulardatafilepath, 'w') as f:
            json.dump({'account': self.account, 'partition': self.partition}, f, indent=4)
        with open(metadatafilepath, 'w') as f:
            json.dump(self.metadata, f, indent=4)
        with open(nodesfilepath, 'w') as f:
            json.dump([node.to_dictionary() for node in self.nodes], f, indent=4)
        with open(edgesfilepath, 'w') as f:
            json.dump([edge.to_dictionary() for edge in self.edges], f, indent=4)
        with open(policiesfilepath, 'w') as f:
            json.dump([policy.to_dictionary() for policy in self.policies], f, indent=4)
        with open(groupsfilepath, 'w') as f:
            json.dump([group.to_dictionary() for group in self.groups], f, indent=4)
        os.umask(old_umask)

    @classmethod
    def create_graph_from_local_disk(cls, root_directory: str):
        """Generates a Graph object by pulling data from disk at root_directory.

        Structure:
        | <root_directory parameter>
        |---- data.json
        |---- metadata.json
        |---- graph/
        |-------- nodes.json
        |-------- edges.json
        |-------- policies.json
        |-------- groups.json

        Loads metadata, then policies, then groups, then nodes, then edges. Specific ordering is for handling
        different dependencies when generating the objects.

        Validates, using metadata, that the version of Principal Mapper that created the graph is the same
        major/minor version of the current version of Principal Mapper. Raises a ValueError otherwise.
        """
        logger.debug('Loading Graph object from {}'.format(root_directory))
        rootpath = root_directory
        if not os.path.exists(rootpath):
            raise ValueError('Did not find file at: {}'.format(rootpath))
        graphdir = os.path.join(rootpath, 'graph')
        metadatafilepath = os.path.join(rootpath, 'metadata.json')
        regulardatafilepath = os.path.join(rootpath, 'data.json')
        nodesfilepath = os.path.join(graphdir, 'nodes.json')
        edgesfilepath = os.path.join(graphdir, 'edges.json')
        policiesfilepath = os.path.join(graphdir, 'policies.json')
        groupsfilepath = os.path.join(graphdir, 'groups.json')

        with open(metadatafilepath) as f:
            metadata = json.load(f)

        current_pmapper_version = packaging.version.parse(principalmapper.__version__)
        loaded_graph_version = packaging.version.parse(metadata['pmapper_version'])
        if current_pmapper_version.major != loaded_graph_version.major or current_pmapper_version.minor != loaded_graph_version.minor:
            raise ValueError(
                f'The loaded Graph data came from a different version of Principal Mapper '
                f'({str(loaded_graph_version)}) that is not compatible with this version of Principal Mapper '
                f'({str(current_pmapper_version)}). You will need to recreate the organization (`pmapper orgs '
                f'create`).'
            )

        with open(regulardatafilepath) as f:
            acctdata = json.load(f)  # type: dict

        policies = []
        with open(policiesfilepath) as f:
            policies_file_contents = json.load(f)

        for policy in policies_file_contents:
            policies.append(Policy(arn=policy['arn'], name=policy['name'], policy_doc=policy['policy_doc']))

        with open(groupsfilepath) as f:
            unresolved_groups = json.load(f)
        groups = []
        for group in unresolved_groups:
            # dig through string list of attached policies to match up with policy objects with matching ARNs
            group_policies = []
            for policy_ref in group['attached_policies']:
                for policy in policies:
                    if policy_ref['arn'] == policy.arn and policy_ref['name'] == policy.name:
                        group_policies.append(policy)
                        break
            groups.append(Group(arn=group['arn'], attached_policies=group_policies))

        with open(nodesfilepath) as f:
            unresolved_nodes = json.load(f)
        nodes = []
        for node in unresolved_nodes:
            # dig through string list of groups and policies to match up with group and policy objects
            node_policies = []
            group_memberships = []
            for policy_ref in node['attached_policies']:
                for policy in policies:
                    if policy_ref['arn'] == policy.arn and policy_ref['name'] == policy.name:
                        node_policies.append(policy)
                        break
            # match permission boundaries
            node_permission_boundary = node['permissions_boundary']
            if node_permission_boundary is not None:
                # find policy by arn/name and load
                for policy in policies:
                    if policy.name == node_permission_boundary['name'] and policy.arn == node_permission_boundary['arn']:
                        node_permission_boundary = policy
                        break

            for group in groups:
                if group.arn in node['group_memberships']:
                    group_memberships.append(group)
            nodes.append(Node(arn=node['arn'], id_value=node['id_value'], attached_policies=node_policies,
                              group_memberships=group_memberships, trust_policy=node['trust_policy'],
                              instance_profile=node['instance_profile'], num_access_keys=node['access_keys'],
                              active_password=node['active_password'], is_admin=node['is_admin'],
                              permissions_boundary=node_permission_boundary, has_mfa=node['has_mfa'], tags=node['tags']))

        with open(edgesfilepath) as f:
            unresolved_edges = json.load(f)
        edges = []
        for edge in unresolved_edges:
            # dig through nodes to find matching ARNs
            source = None
            destination = None
            for node in nodes:
                if source is None and node.arn == edge['source']:
                    source = node
                if destination is None and node.arn == edge['destination']:
                    destination = node
                if source is not None and destination is not None:
                    break
            edges.append(Edge(source=source, destination=destination, reason=edge['reason'],
                              short_reason=edge['short_reason']))

        return Graph(
            nodes=nodes,
            edges=edges,
            policies=policies,
            groups=groups,
            account=acctdata.get('account'),
            partition=acctdata.get('partition'),
            metadata=metadata
        )
