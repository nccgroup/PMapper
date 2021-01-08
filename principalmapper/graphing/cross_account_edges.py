"""Code to derive a collection of edges between different Graph objects."""

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

import datetime as dt
import logging
from typing import List

from principalmapper.common import Edge, Graph
from principalmapper.querying.query_interface import resource_policy_authorization, ResourcePolicyEvalResult


logger = logging.getLogger(__name__)


def get_edges_between_graphs(graph_a: Graph, graph_b: Graph) -> List[Edge]:
    """Given two Graph objects, return a list of Edge objects that represent the connections between
    the two Graphs (both to and from). Currently only does sts:AssumeRole checks."""

    result = []  # type: List[Edge]

    def _check_assume_role(ga, na, gb, nb) -> bool:
        logger.debug('Checking if {} can access {}'.format(na.arn, nb.arn))

        # load up conditions: inspired by _infer_condition_keys
        conditions = {}
        conditions['aws:CurrentTime'] = dt.datetime.now(dt.timezone.utc).isoformat()
        conditions['aws:EpochTime'] = str(round(dt.datetime.now(dt.timezone.utc).timestamp()))
        conditions['aws:userid'] = na.id_value

        if ':user/' in na.arn:
            conditions['aws:username'] = na.searchable_name().split('/')[1]

        conditions['aws:SecureTransport'] = 'true'
        conditions['aws:PrincipalAccount'] = ga.metadata['account_id']
        conditions['aws:PrincipalArn'] = na.arn
        if 'org-id' in ga.metadata:
            conditions['aws:PrincipalOrgID'] = ga.metadata['org-id']
        if 'org-path' in ga.metadata:
            conditions['aws:PrincipalOrgPaths'] = ga.metadata['org-path']

        for tag_key, tag_value in na.tags.items():
            conditions['aws:PrincipalTag/{}'.format(tag_key)] = tag_value

        # check without MFA
        rp_result = resource_policy_authorization(
            na,
            gb.metadata['account_id'],
            nb.trust_policy,
            'sts:AssumeRole',
            nb.arn,
            conditions
        )

        if rp_result == ResourcePolicyEvalResult.DIFF_ACCOUNT_MATCH:
            return True

        # check with MFA
        conditions.update({
            'aws:MultiFactorAuthAge': '1',
            'aws:MultiFactorAuthPresent': 'true'
        })
        rp_result = resource_policy_authorization(
            na,
            gb.metadata['account_id'],
            nb.trust_policy,
            'sts:AssumeRole',
            nb.arn,
            {
                'aws:MultiFactorAuthAge': '1',
                'aws:MultiFactorAuthPresent': 'true'
            }
        )

        return rp_result == ResourcePolicyEvalResult.DIFF_ACCOUNT_MATCH

    for node_a in graph_a.nodes:
        for node_b in graph_b.nodes:
            # check a -> b
            if node_b.searchable_name().startswith('role/'):
                if _check_assume_role(graph_a, node_a, graph_b, node_b):
                    result.append(Edge(node_a, node_b, 'can call sts:AssumeRole to access', 'STS'))

            # check b -> a
            if node_a.searchable_name().startswith('role/'):
                if _check_assume_role(graph_b, node_b, graph_a, node_a):
                    result.append(Edge(node_b, node_a, 'can call sts:AssumeRole to access', 'STS'))

    return result
