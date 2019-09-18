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
import os
from typing import List

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface


class IAMEdgeChecker(EdgeChecker):
    """Class for identifying if IAM can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], output: io.StringIO = os.devnull, debug: bool = False) -> List[Edge]:
        """Fulfills expected method return_edges."""
        result = []
        for node_source in nodes:
            for node_destination in nodes:
                # skip self-access checks
                if node_source == node_destination:
                    continue

                # check if source is an admin, if so it can access destination but this is not tracked via an Edge
                if node_source.is_admin:
                    continue

                if ':user/' in node_destination.arn:
                    # Change the user's access keys
                    access_keys_mfa = False

                    create_auth_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'iam:CreateAccessKey',
                        node_destination.arn,
                        {},
                        debug
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
                            debug
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
                                node_source, node_destination, reason
                            )
                        )

                    # Change the user's password
                    if node_destination.active_password:
                        pass_auth_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                            node_source,
                            'iam:UpdateLoginProfile',
                            node_destination.arn,
                            {},
                            debug
                        )
                    else:
                        pass_auth_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                            node_source,
                            'iam:CreateLoginProfile',
                            node_destination.arn,
                            {},
                            debug
                        )
                    if pass_auth_res:
                        reason = 'can set the password to authenticate as'
                        if mfa_res:
                            reason = '(MFA required) ' + reason
                        result.append(Edge(node_source, node_destination, reason))

                if ':role/' in node_destination.arn:
                    # Change the role's trust doc
                    update_role_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'iam:UpdateAssumeRolePolicy',
                        node_destination.arn,
                        {},
                        debug
                    )
                    if update_role_res:
                        reason = 'can update the trust document to access'
                        if mfa_res:
                            reason = '(MFA required) ' + reason
                        result.append(Edge(node_source, node_destination, reason))

        for edge in result:
            output.write("Found new edge: {}\n".format(edge.describe_edge()))
        return result
