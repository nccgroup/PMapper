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

import copy
import logging
import re
from typing import List, Dict

from principalmapper.common import Graph, Policy, Node
from principalmapper.querying import query_interface
from principalmapper.util.case_insensitive_dict import CaseInsensitiveDict

_service_resource_exposure_map = {
    's3': {
        'pattern': re.compile(r"^arn:aws:s3:::[^/]+$"),
        'actions': ['s3:PutBucketPolicy']
    },
    'sns': {
        'pattern': re.compile(r"^arn:aws:sns:[a-z0-9-]+:[0-9]+:.*"),
        'actions': ['sns:AddPermission', 'sns:SetTopicAttributes']
    },
    'sqs': {
        'pattern': re.compile(r"^arn:aws:sqs:[a-z0-9-]+:[0-9]+:.*"),
        'actions': ['sqs:AddPermission', 'sqs:SetQueueAttributes']
    },
    'kms': {
        'pattern': re.compile(r"^arn:aws:kms:[a-z0-9-]+:[0-9]+:key/.*"),
        'actions': ['kms:PutKeyPolicy']
    },
    'secretsmanager': {
        'pattern': re.compile(r"^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]+:.*"),
        'actions': ['secretsmanager:PutResourcePolicy']
    }
}


def handle_preset_query(graph: Graph, tokens: List[str], skip_admins: bool = False) -> None:
    """Handles a human-readable query that's been chunked into tokens, and prints the results. Prints out the relevant
    resources vs nodes and marks the relevant cells where a principal can alter the resource policy and broaden it
    to world-read.

    Tokens should be:

    * "preset"
    * "endgame"
    * <service> : (*|s3|sns|sqs|kms|secretsmanager)
    """
    endgame_map = compose_endgame_map(graph, tokens[2], skip_admins)
    for policy, nodes in endgame_map.items():
        print(policy.arn)
        print('  {}'.format([x.searchable_name() for x in nodes]))


def compose_endgame_map(graph: Graph, service_to_include: str = '*', skip_admins: bool = False) -> Dict[Policy, List[Node]]:
    """Given a Graph and a service to look at, compose and return a map that includes the different
    users/roles versus the resources they're able to open up for world-access."""

    result = {}

    for policy in graph.policies:
        for service, definition in _service_resource_exposure_map.items():
            if service_to_include == '*' or ':{}:'.format(service_to_include) in policy.arn:
                if definition['pattern'].match(policy.arn) is not None:
                    result[policy] = []

                    for node in graph.nodes:
                        node_confirmed = False

                        if 'conditions' not in node.cache:
                            node.cache['conditions'] = query_interface._infer_condition_keys(node, CaseInsensitiveDict())

                        if (not skip_admins) or (not node.is_admin):
                            for action in definition['actions']:
                                if node_confirmed:
                                    continue

                                query_result = query_interface.local_check_authorization_full(
                                    node, action, policy.arn, node.cache['conditions'], policy.policy_doc, graph.metadata['account_id'],
                                    None, None
                                )

                                if query_result:
                                    node_confirmed = True

                                elif node.has_mfa:
                                    conditions_copy = copy.deepcopy(node.cache['conditions'])
                                    conditions_copy.update({
                                        'aws:MultiFactorAuthAge': '1',
                                        'aws:MultiFactorAuthPresent': 'true'
                                    })
                                    query_result = query_interface.local_check_authorization_full(
                                        node, action, policy.arn, conditions_copy, policy.policy_doc,
                                        graph.metadata['account_id'],
                                        None, None
                                    )
                                    if query_result:
                                        node_confirmed = True

                        if node_confirmed:
                            result[policy].append(node)

    return result
