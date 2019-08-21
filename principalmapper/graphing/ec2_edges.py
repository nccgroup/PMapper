"""Code to identify if a principal in an AWS account can use access to EC2 to access other principals."""

import io
import os
from typing import List

from principalmapper.common.edges import Edge
from principalmapper.common.nodes import Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.util import arns


class EC2EdgeChecker(EdgeChecker):
    """Goes through the IAM service to locate potential edges between nodes."""

    def return_edges(self, nodes: List[Node], output: io.StringIO = os.devnull, debug: bool = False) -> List[Edge]:
        """Fulfills expected method return_edges. If session object is None, runs checks in offline mode."""
        result = []

        for node_source in nodes:
            for node_destination in nodes:
                # skip self-access checks
                if node_source == node_destination:
                    continue

                # check if source is an admin, if so it can access destination but this is not tracked via an Edge
                if node_source.is_admin:
                    continue

                # check if destination is a user, skip if so
                if ':user/' in node_destination.arn:
                    continue

                # check that the destination role can be assumed by EC2
                sim_result = resource_policy_authorization(
                    'ec2.amazonaws.com',
                    arns.get_account_id(node_source.arn),
                    node_destination.trust_policy,
                    'sts:AssumeRole',
                    node_destination.arn,
                    {},
                    debug
                )

                if sim_result != ResourcePolicyEvalResult.SERVICE_MATCH:
                    continue  # EC2 wasn't auth'd to assume the role

                # check if source can pass the destination role
                condition_keys = {'iam:PassedToService': 'ec2.amazonaws.com'}
                pass_role_auth, need_mfa_to_pass = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'iam:PassRole',
                    node_destination.arn,
                    condition_keys,
                    debug
                )
                if not pass_role_auth:
                    continue  # source can't pass the role to use it

                # check if destination has an instance profile, if not: check if source can create it
                need_mfa_for_ip = False
                if node_destination.instance_profile is None:
                    create_ip_auth, need_mfa_0 = query_interface.local_check_authorization_handling_mfa(
                        node_source, 'iam:CreateInstanceProfile', '*', {}, debug)
                    if not create_ip_auth:
                        continue  # node_source can't make the instance profile
                    if need_mfa_0:
                        need_mfa_for_ip = True

                    create_ip_auth, need_mfa_0 = query_interface.local_check_authorization_handling_mfa(
                        node_source, 'iam:AddRoleToInstanceProfile', node_destination.arn, {}, debug)
                    if not create_ip_auth:
                        continue  # node_source can't attach a new instance profile to node_destination
                    if need_mfa_0:
                        need_mfa_for_ip = True

                # check if source can run an instance with the instance profile condition, add edge if so and continue
                iprofile = node_destination.instance_profile if node_destination.instance_profile is not None else '*'
                condition_keys = {'ec2:InstanceProfile': iprofile}
                if query_interface.local_check_authorization(node_source, 'ec2:RunInstances', '*', condition_keys,
                                                             debug):
                    if iprofile is not None:
                        reason = 'can use EC2 to run an instance with an existing instance profile to access'
                    else:
                        reason = 'can use EC2 to run an instance with a newly created instance profile to access'
                    new_edge = Edge(
                        node_source,
                        node_destination,
                        reason
                    )
                    output.write('Found new edge: {}\n'.format(new_edge.describe_edge()))
                    result.append(new_edge)

                # check if source can run an instance without an instance profile then add the profile, add edge if so
                if query_interface.local_check_authorization(node_source, 'ec2:RunInstances', '*', {}, debug):
                    if iprofile is not None:
                        reason = 'can use EC2 to run an instance and then attach an existing instance profile to access'
                    else:
                        reason = 'can use EC2 to run an instance and then attach a newly created instance profile to ' \
                                 'access'
                    new_edge = Edge(
                        node_source,
                        node_destination,
                        reason
                    )
                    output.write('Found new edge: {}\n'.format(new_edge.describe_edge()))
                    result.append(new_edge)

        return result
