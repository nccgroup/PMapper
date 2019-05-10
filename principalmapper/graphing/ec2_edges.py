"""Code to identify if a principal in an AWS account can use access to EC2 to access other principals."""

import io
import os
from typing import List

from principalmapper.common.edges import Edge
from principalmapper.common.nodes import Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface


class EC2EdgeChecker(EdgeChecker):
    """Goes through the IAM service to locate potential edges between nodes."""

    def return_edges(self, nodes: List[Node], output: io.StringIO = os.devnull, debug: bool = False) -> List[Edge]:
        """Fulfills expected method return_edges. If session object is None, runs checks in offline mode."""
        result = []
        if self.session is not None:
            iamclient = self.session.create_client('iam')
        else:
            iamclient = None

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

                # check that EC2 can assume the role
                allow_check = query_interface.resource_policy_has_matching_statement_for_service(
                    'ec2.amazonaws.com',
                    node_destination.trust_policy,
                    'Allow', 'sts:AssumeRole',
                    node_destination.arn,
                    {},
                    debug
                )
                deny_check = query_interface.resource_policy_has_matching_statement_for_service(
                    'ec2.amazonaws.com',
                    node_destination.trust_policy,
                    'Deny',
                    'sts:AssumeRole',
                    node_destination.arn,
                    {},
                    debug
                )
                if deny_check or not allow_check:
                    continue  # EC2 can't assume the role, so we can't use it as an instance profile's role

                # check if source can pass the destination role
                condition_keys = {'iam:PassedToService': 'ec2.amazonaws.com'}
                if not query_interface.is_authorized_for(iamclient, node_source, 'iam:PassRole', node_destination.arn,
                                                         condition_keys, iamclient is not None, debug):
                    continue  # source can't pass the destination role, which is checked at launch or association

                # check if destination has an instance profile, if not: check if source can create it
                if node_destination.trust_policy is None:
                    if not query_interface.is_authorized_for(iamclient, node_source, 'iam:CreateInstanceProfile',
                                                             '*', {}, iamclient is not None, debug):
                        continue  # destination doesn't have an instance profile, source can't make one

                    if not query_interface.is_authorized_for(iamclient, node_source, 'iam:AddRoleToInstanceProfile',
                                                             node_destination.arn, {}, iamclient is not None, debug):
                        continue  # source can make an instance profile but cannot attach it

                # check if source can run an instance with the instance profile condition, add edge if so and continue
                iprofile = node_destination.instance_profile if node_destination.instance_profile is not None else '*'
                condition_keys = {'ec2:InstanceProfile': iprofile}
                if query_interface.is_authorized_for(iamclient, node_source, 'ec2:RunInstances', '*', condition_keys,
                                                     iamclient is not None, debug):
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
                if query_interface.is_authorized_for(iamclient, node_source, 'ec2:RunInstances', '*', {},
                                                     iamclient is not None, debug):
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
