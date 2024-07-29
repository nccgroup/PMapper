"""Code to identify if a principal in an AWS account can use access to IAM to access other principals."""


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

import io
import logging
import os
from typing import List, Optional

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface

from multiprocessing import Pool, Manager, cpu_count
from multiprocessing.queues import Queue
from rich.progress import Progress
import time


logger = logging.getLogger(__name__)


class IAMEdgeChecker(EdgeChecker):
    """Class for identifying if IAM can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Fulfills expected method return_edges."""

        logger.info('Generating Edges based on IAM')
        result = generate_edges_locally(nodes, scps)

        for edge in result:
            logger.info("Found new edge: {}\n".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None) -> List[Edge]:
    """Generates and returns Edge objects. It is possible to use this method if you are operating offline (infra-as-code).
    """

    edges = []
    role_nodes = [node for node in nodes if ':role/' in node.arn and not node.is_admin]
    total_nodes = len(role_nodes)

    num_processes = max(cpu_count() - 1, 1)  # Number of CPU cores minus one, but at least 1
    base_batch_size = len(role_nodes) // num_processes
    remainder = len(role_nodes) % num_processes
    batch_size = base_batch_size + (1 if remainder > 0 else 0)

    # Calculate batc.h size
    base_batch_size = len(role_nodes) // num_processes
    remainder = len(role_nodes) % num_processes
    batch_size = base_batch_size + (1 if remainder > 0 else 0)
    
    with Manager() as manager:
        progress_queue = manager.Queue()

        # Create batches of nodes
        batches = [role_nodes[i:i + batch_size] for i in range(0, len(role_nodes), batch_size)]

        with Pool(processes=num_processes) as pool:
            pool_result = pool.starmap_async(process_batch, [(batch, nodes, progress_queue, scps) for batch in batches])

            with Progress() as progress:
                task = progress.add_task("[green]Processing IAM edges...", total=total_nodes)

                while not pool_result.ready():
                    try:
                        while not progress_queue.empty():
                            progress.advance(task, progress_queue.get_nowait())
                        time.sleep(0.1)
                    except KeyboardInterrupt:
                        pool.terminate()
                        break
                
                # Final drain in case any items are left in the queue
                while not progress_queue.empty():
                    progress.advance(task, progress_queue.get_nowait())

        results = pool_result.get()
        for result in results:
            edges.extend(result)

    return edges


def process_batch(batch: List[Node], nodes: List[Node], progress_queue: Queue, scps: Optional[List[List[dict]]] = None):
    result = []

    for node_source in batch:
        for node_destination in nodes:
            # skip self-access checks
            if node_source == node_destination:
                continue

            if ':user/' in node_destination.arn:
                # Change the user's access keys
                access_keys_mfa = False

                create_auth_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'iam:CreateAccessKey',
                    node_destination.arn,
                    {},
                    service_control_policy_groups=scps
                )

                if mfa_res:
                    access_keys_mfa = True

                if node_destination.access_keys == 2:
                    # can have a max of two access keys, need to delete before making a new one
                    auth_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'iam:DeleteAccessKey',
                        node_destination.arn,
                        {},
                        service_control_policy_groups=scps
                    )
                    if not auth_res:
                        create_auth_res = False  # can't delete target access key, can't generate a new one
                    if mfa_res:
                        access_keys_mfa = True

                if create_auth_res:
                    reason = 'can create access keys to authenticate as'
                    if access_keys_mfa:
                        reason = '(MFA required) ' + reason

                    result.append(
                        Edge(
                            node_source, node_destination, reason, 'IAM'
                        )
                    )

                # Change the user's password
                if node_destination.active_password:
                    pass_auth_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'iam:UpdateLoginProfile',
                        node_destination.arn,
                        {},
                        service_control_policy_groups=scps
                    )
                else:
                    pass_auth_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'iam:CreateLoginProfile',
                        node_destination.arn,
                        {},
                        service_control_policy_groups=scps
                    )
                if pass_auth_res:
                    reason = 'can set the password to authenticate as'
                    if mfa_res:
                        reason = '(MFA required) ' + reason
                    result.append(Edge(node_source, node_destination, reason, 'IAM'))

            if ':role/' in node_destination.arn:
                # Change the role's trust doc
                update_role_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'iam:UpdateAssumeRolePolicy',
                    node_destination.arn,
                    {},
                    service_control_policy_groups=scps
                )
                if update_role_res:
                    reason = 'can update the trust document to access'
                    if mfa_res:
                        reason = '(MFA required) ' + reason
                    result.append(Edge(node_source, node_destination, reason, 'IAM'))
        
        progress_queue.put(1)

    return result
