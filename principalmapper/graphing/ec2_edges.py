"""Code to identify if a principal in an AWS account can use access to EC2 to access other principals."""


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

from botocore.exceptions import ClientError

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.util import arns, botocore_tools

from multiprocessing import Pool, Manager, cpu_count
from multiprocessing.queues import Queue
from rich.progress import Progress
import time


logger = logging.getLogger(__name__)


class EC2EdgeChecker(EdgeChecker):
    """Class for identifying if EC2 can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Fulfills expected method return_edges."""

        logger.info('Pulling data on EC2 instances.')
        iam_client = self.session.create_client('iam')
        instance_profile_cache = dict()

        if client_args_map is None:
            cfargs = {}
        else:
            cfargs = client_args_map.get('ec2', {})

        # Grab existing EC2 instances in each region
        ec2_clients = []
        if self.session is not None:
            ec2_regions = botocore_tools.get_regions_to_search(self.session, 'ec2', region_allow_list, region_deny_list)
            for region in ec2_regions:
                ec2_clients.append(self.session.create_client('ec2', region_name=region, **cfargs))

        # grab existing EC2 instances
        ec2_list = []
        for ec2_client in ec2_clients:
            logger.debug('Looking at region {}'.format(ec2_client.meta.region_name))
            try:
                paginator = ec2_client.get_paginator('describe_instances')
                for page in paginator.paginate():
                    for ec2_reservation in page['Reservations']:
                        for ec2_instance in ec2_reservation['Instances']:
                            if ec2_instance['State']['Name'] not in ['terminated'] and 'IamInstanceProfile' in ec2_instance:
                                instance_profile_arn = ec2_instance['IamInstanceProfile']['Arn']

                                if instance_profile_arn in instance_profile_cache:
                                    ec2_roles = instance_profile_cache[instance_profile_arn]
                                else:
                                    instance_profile_name = instance_profile_arn.split('/')[-1]
                                    ec2_roles = iam_client.get_instance_profile(InstanceProfileName=instance_profile_name)['InstanceProfile']['Roles']
                                    instance_profile_cache[instance_profile_arn] = ec2_roles

                                ec2_instance['Roles'] = ec2_roles
                                ec2_list.append(ec2_instance)
            except ClientError as ex:
                logger.warning('Unable to search region {} for EC2 instances. The region may be disabled, or the error may '
                               'be caused by an authorization issue. Continuing.'.format(ec2_client.meta.region_name))
                logger.debug('Exception details: {}'.format(ex))

        logger.info('Generating Edges based on data from EC2.')
        result = generate_edges_locally(nodes, ec2_list, scps)

        for edge in result:
            logger.info("Found new edge: {}".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], ec2_list: List[dict], scps: Optional[List[List[dict]]] = None) -> List[Edge]:

    """Generates and returns Edge objects. It is possible to use this method if you are operating offline (infra-as-code).
    """
    edges = []

    for ec2_instance in ec2_list:
        for node_destination in _get_ec2_nodes(nodes, ec2_instance):
            for node_source in nodes:
                # skip self-access checks
                if node_source == node_destination:
                    continue

                # check if source is an admin: if so, it can access destination but this is not tracked via an Edge
                if node_source.is_admin:
                    continue

                # check if source can modify user data of EC2 instance
                can_update, need_mfa_update = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'ec2:ModifyInstanceAttribute',
                    ec2_instance['InstanceId'],
                    {'ec2:RoleArn': node_destination.arn},
                    service_control_policy_groups=scps
                )

                if can_update:
                    reason = 'can update EC2 user data to obtain access to'
                    if need_mfa_update:
                        reason = '(MFA required) ' + reason

                    new_edge = Edge(
                        node_source,
                        node_destination,
                        reason,
                        'EC2'
                    )
                    result.append(new_edge)

    # Filter for roles
    role_nodes = [node for node in nodes if ':role/' in node.arn]
    total_nodes = len(role_nodes)
    # Number of CPU cores minus one, but at least 1
    num_processes = max(cpu_count() - 1, 1)  
    # Calculate batch size
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
                task = progress.add_task("[green]Processing EC2 edges...", total=total_nodes)

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
    for node_destination in batch:
        # check that the destination role can be assumed by EC2
        sim_result = resource_policy_authorization(
            'ec2.amazonaws.com',
            arns.get_account_id(node_destination.arn),
            node_destination.trust_policy,
            'sts:AssumeRole',
            node_destination.arn,
            {},
        )

        if sim_result != ResourcePolicyEvalResult.SERVICE_MATCH:
            progress_queue.put(1)
            continue  # EC2 wasn't auth'd to assume the role

        for node_source in nodes:
            # skip self-access checks
            if node_source == node_destination:
                continue

            # check if source is an admin: if so, it can access destination but this is not tracked via an Edge
            if node_source.is_admin:
                continue

            # check if source can pass the destination role
            mfa_needed = False
            condition_keys = {'iam:PassedToService': 'ec2.amazonaws.com'}
            pass_role_auth, mfa_res = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'iam:PassRole',
                node_destination.arn,
                condition_keys,
                service_control_policy_groups=scps
            )
            if not pass_role_auth:
                continue  # source can't pass the role to use it

            # check if destination has an instance profile, if not: check if source can create it
            if node_destination.instance_profile is None:
                create_ip_auth, mfa_res = query_interface.local_check_authorization_handling_mfa(
                    node_source, 'iam:CreateInstanceProfile', '*', {}, service_control_policy_groups=scps)
                if not create_ip_auth:
                    continue  # node_source can't make the instance profile
                if mfa_res:
                    mfa_needed = True

                create_ip_auth, mfa_res = query_interface.local_check_authorization_handling_mfa(
                    node_source, 'iam:AddRoleToInstanceProfile', node_destination.arn, {}, service_control_policy_groups=scps)
                if not create_ip_auth:
                    continue  # node_source can't attach a new instance profile to node_destination
                if mfa_res:
                    mfa_needed = True

            # check if source can run an instance with the instance profile condition, add edge if so and continue
            if node_destination.instance_profile is not None and len(node_destination.instance_profile) > 0:
                iprofile = node_destination.instance_profile[0]
                condition_keys = {'ec2:InstanceProfile': iprofile}
            else:
                iprofile = '*'
                condition_keys = {}

            create_instance_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'ec2:RunInstances',
                '*',
                condition_keys,
                service_control_policy_groups=scps
            )

            if mfa_res:
                mfa_needed = True

            if create_instance_res:
                if iprofile != '*':
                    reason = 'can use EC2 to run an instance with an existing instance profile to access'
                else:
                    reason = 'can use EC2 to run an instance with a newly created instance profile to access'
                if mfa_needed:
                    reason = '(MFA required) ' + reason

                new_edge = Edge(
                    node_source,
                    node_destination,
                    reason,
                    'EC2'
                )
                result.append(new_edge)

            # check if source can run an instance without an instance profile then add the profile, add edge if so
            create_instance_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'ec2:RunInstances',
                '*',
                {},
                service_control_policy_groups=scps
            )

            if mfa_res:
                mfa_needed = True

            if create_instance_res:
                attach_ip_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'ec2:AssociateIamInstanceProfile',
                    '*',
                    condition_keys,
                    service_control_policy_groups=scps
                )

                if iprofile != '*':
                    reason = 'can use EC2 to run an instance and then associate an existing instance profile to ' \
                             'access'
                else:
                    reason = 'can use EC2 to run an instance and then attach a newly created instance profile to ' \
                             'access'

                if mfa_res or mfa_needed:
                    reason = '(MFA required) ' + reason

                if attach_ip_res:
                    new_edge = Edge(
                        node_source,
                        node_destination,
                        reason,
                        'EC2'
                    )
                    result.append(new_edge)

        progress_queue.put(1)
    
    return result


def _get_ec2_nodes(nodes, ec2_instance):
    node_destinations = []

    for ec2_role in ec2_instance['Roles']:
        for node in nodes:
            if node.arn == ec2_role['Arn']:
                node_destinations.append(node)
                break

    return node_destinations