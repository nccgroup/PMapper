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
from principalmapper.querying.local_policy_simulation import _listify_string
from principalmapper.util.case_insensitive_dict import CaseInsensitiveDict


logger = logging.getLogger(__name__)


def handle_preset_query(graph: Graph, tokens: List[str], skip_admins: bool = False) -> None:
    """Handles a human-readable query that's been chunked into tokens, and prints the results. Prints out the relevant
    roles in the account that a service can assume.

    Tokens should be:

    * "preset"
    * "endgame"
    * <service> : (*|s3|sns|sqs|kms|secretsmanager)
    """

    sam = compose_service_access_map(graph)
    for service, roles in sam.items():
        print(service)
        print('    ' + str([x.arn.split('/')[-1] for x in roles]))


def compose_service_access_map(graph: Graph) -> Dict[str, List[Node]]:
    """Given a Graph, create a mapping from services to the IAM Roles in the Graph they can assume."""
    result = {}

    # iterate through all nodes
    for n in graph.nodes:  # type: Node
        # filter to IAM Roles
        if ':role/' not in n.arn:
            continue

        allow_list = []
        deny_list = []
        if 'Statement' not in n.trust_policy:
            continue

        for stmt in n.trust_policy['Statement']:
            if 'Principal' not in stmt:
                continue  # TODO: re-examine inclusion of NotPrincipal in trust docs
            if 'Service' in stmt['Principal']:
                for element in _listify_string(stmt['Principal']['Service']):
                    if stmt['Effect'] == 'Allow':
                        allow_list.append(element)
                    else:
                        deny_list.append(element)

        for allowed in allow_list:
            if allowed in deny_list:
                continue

            if allowed not in result:
                result[allowed] = [n]
            else:
                result[allowed].append(n)

    return result
