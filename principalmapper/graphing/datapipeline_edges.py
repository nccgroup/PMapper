"""Code to identify if a principal in an AWS account can use access to Data Pipeline to access other principals."""


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

import io
import logging
import os
from typing import List, Optional

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.util import arns, botocore_tools


logger = logging.getLogger(__name__)


class DataPipelineEdgeChecker(EdgeChecker):
    """Class for identifying if IAM can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Fulfills expected method return_edges."""

        logger.info('Generating Edges based on Data Pipeline')

        dp_args = client_args_map.get('datapipeline', {})

        # Grab existing pipelines
        dp_clients = []
        if self.session is not None:
            dp_regions = botocore_tools.get_regions_to_search(self.session, 'datapipeline', region_allow_list, region_deny_list)
            for region in dp_regions:
                dp_clients.append(self.session.create_client('datapipeline', region_name=region, **dp_args))

        pipeline_list = []
        for dp_client in dp_clients:
            logger.debug('Looking at region {}'.format(dp_client))
            # TODO: pull pipelines, paginate?

        result = generate_edges_locally(nodes, scps)

        for edge in result:
            logger.info("Found new edge: {}\n".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None) -> List[Edge]:
    """Generates and returns Edge objects. It is possible to use this method if you are operating offline (infra-as-code).
    """
    result = []

    for node_source in nodes:
        for node_destination in nodes:
            # skip self-access checks
            if node_source == node_destination:
                continue

            # check if source is an admin, if so it can access destination but this is not tracked via an Edge
            if node_source.is_admin:
                continue



    return result
