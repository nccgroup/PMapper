"""Code for querying a graph about specific access to actions and resources in AWS"""


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

import copy
import hashlib
import logging

from principalmapper.common import Graph
from principalmapper.querying import query_utils
from principalmapper.querying.local_policy_simulation import *
from principalmapper.querying.query_result import QueryResult
from principalmapper.util import arns


logger = logging.getLogger(__name__)


def search_authorization_for(graph: Graph, principal: Node, action_to_check: str, resource_to_check: str,
                             condition_keys_to_check: dict, debug: bool = False) -> QueryResult:
    """Determines if the passed principal, or any principals it can access, can perform a given action for a
    given resource/condition."""

    if local_check_authorization(principal, action_to_check, resource_to_check, condition_keys_to_check, debug):
        return QueryResult(True, [], principal)

    # Invoke special-case if admin node is not directly authorized to call the given action for the given resource
    if principal.is_admin:
        return QueryResult(True, principal, principal)

    for edge_list in query_utils.get_search_list(graph, principal):
        if local_check_authorization(edge_list[-1].destination, action_to_check, resource_to_check,
                                     condition_keys_to_check, debug):
            return QueryResult(True, edge_list, principal)

    return QueryResult(False, [], principal)


def search_authorization_with_resource_policy_for(graph: Graph, principal: Node, action_to_check: str,
                                                  resource_to_check: str, condition_keys_to_check: dict,
                                                  resource_policy: dict, resource_owner: str,
                                                  debug: bool = False) -> QueryResult:
    """Determines if the passed principal, or any principals it can access, can perform a given action for a
    given resource/condition while accounting for the passed resource policy."""

    if local_check_authorization_with_resource_policy(principal, action_to_check, resource_to_check,
                                                      condition_keys_to_check, resource_policy, resource_owner, debug):
        return QueryResult(True, [], principal)

    # We do NOT assume admins have access due to cross-account scenarios, but we're gonna be looking through a LOT
    # of generated admin edges otherwise
    for edge_list in query_utils.get_search_list(graph, principal):
        if local_check_authorization_with_resource_policy(principal, action_to_check, resource_to_check,
                                                          condition_keys_to_check, resource_policy, resource_owner,
                                                          debug):
            return QueryResult(True, edge_list, principal)

    return QueryResult(False, [], principal)


def _infer_condition_keys(principal: Node, current_keys: dict) -> dict:
    """Returns a dictionary with global condition context keys we can infer are set based on the input Node being
    checked. We exclude setting keys that are already set in current_keys.

    Using information from https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
    """

    result = {}

    # Date and Time: aws:CurrentTime and aws:EpochTime
    # TODO: Examine if using datetime.isoformat() is good enough to avoid bugs
    if 'aws:CurrentTime' not in current_keys:
        result['aws:CurrentTime'] = dt.datetime.now(dt.timezone.utc).isoformat()

    if 'aws:EpochTime' not in current_keys:
        result['aws:EpochTime'] = str(round(dt.datetime.now(dt.timezone.utc).timestamp()))

    # UserID and Username: aws:userid and aws:username
    # TODO: Double-check how roles handle aws:username, IIRC it's not filled in
    if 'aws:userid' not in current_keys:
        result['aws:userid'] = principal.id_value

    if ':user/' in principal.arn and 'aws:username' not in current_keys:
        result['aws:username'] = principal.searchable_name().split('/')[1]

    # TODO: Add aws:SecureTransport and aws:PrincipalArn ?

    return result


def local_check_authorization_handling_mfa(principal: Node, action_to_check: str, resource_to_check: str,
                                           condition_keys_to_check: dict, debug: bool = False) -> (bool, bool):
    """Determine if a node is authorized to make an API call. If the node is an IAM User, it will perform authorization
    checks with and without MFA enabled. It returns a (bool, bool) tuple: if the user was authorized and if MFA was
    required for the authorization.
    """

    if ':role/' in principal.arn:  # TODO: aws:MultiFactorAuthPresent pass-through?
        return local_check_authorization(principal, action_to_check, resource_to_check, condition_keys_to_check,
                                         debug), False

    if local_check_authorization(principal, action_to_check, resource_to_check, condition_keys_to_check, debug):
        return True, False

    new_condition_keys = copy.deepcopy(condition_keys_to_check)
    if 'aws:MultiFactorAuthAge' not in new_condition_keys:
        new_condition_keys.update({'aws:MultiFactorAuthAge': '1'})
    if 'aws:MultiFactorAuthPresent' not in new_condition_keys:
        new_condition_keys.update({'aws:MultiFactorAuthPresent': 'true'})

    if local_check_authorization(principal, action_to_check, resource_to_check, new_condition_keys, debug):
        return True, True

    return False, False


def local_check_authorization(principal: Node, action_to_check: str, resource_to_check: str,
                              condition_keys_to_check: dict, debug: bool = False) -> bool:
    """Determine if a node is authorized to make an API call. It will perform a local evaluation of the attached
    IAM policies to determine authorization.

    NOTE: this will add condition keys that it can infer, assuming they're not set already, such as aws:username or
    aws:userid.
    """

    conditions_keys_copy = copy.deepcopy(condition_keys_to_check)
    conditions_keys_copy.update(_infer_condition_keys(principal, conditions_keys_copy))

    logger.debug('Testing authorization for Principal: {}, Action: {}, Resource: {}, Conditions: {}'.format(
        principal.arn,
        action_to_check,
        resource_to_check,
        conditions_keys_copy
    ))

    # Handle permission boundaries if applicable
    if principal.permissions_boundary is not None:
        if policy_has_matching_statement(principal.permissions_boundary, 'Deny', action_to_check, resource_to_check,
                                         conditions_keys_copy, debug):
            return False
        if not policy_has_matching_statement(principal.permissions_boundary, 'Allow', action_to_check, resource_to_check,
                                             conditions_keys_copy, debug):
            return False

    # must have a matching Allow statement, otherwise it's an implicit deny
    if not has_matching_statement(principal, 'Allow', action_to_check, resource_to_check,
                                  conditions_keys_copy, debug):
        return False

    # must not have a matching Deny statement, otherwise it's an explicit deny
    return not has_matching_statement(principal, 'Deny', action_to_check, resource_to_check,
                                      conditions_keys_copy, debug)


def local_check_authorization_with_resource_policy(principal: Node, action_to_check: str, resource_to_check: str,
                                                   condition_keys_to_check: dict, resource_policy: dict,
                                                   resource_owner: str, debug: bool = False) -> bool:
    """Determine if a given node is authorized to make an API call. It will perform a local evaluation of the
    attached IAM policies of the principal and the given resource policy to determine authorization.

    NOTE: This will add condition keys that may be inferred, assuming they are not already set, such as the
    aws:username or aws:userid keys.
    """

    conditions_keys_copy = copy.deepcopy(condition_keys_to_check)
    conditions_keys_copy.update(_infer_condition_keys(principal, conditions_keys_copy))

    logger.debug('Testing authorization for: principal: {}, action: {}, resource: {}, conditions: {}, Resource Policy: {}'.format(
        principal.arn,
        action_to_check,
        resource_to_check,
        conditions_keys_copy,
        resource_policy
    ))

    # Pull permissions boundary data
    if principal.permissions_boundary is not None:
        pb_deny = policy_has_matching_statement(principal.permissions_boundary, 'Deny', action_to_check,
                                                resource_to_check, conditions_keys_copy, debug)
        pb_allow = policy_has_matching_statement(principal.permissions_boundary, 'Allow', action_to_check,
                                                 resource_to_check, conditions_keys_copy, debug)
    else:
        pb_deny, pb_allow = None, None

    # Pull resource policy authorization data
    rp_result = resource_policy_authorization(principal, resource_owner, resource_policy, action_to_check,
                                              resource_to_check, conditions_keys_copy, debug)

    # Pull IAM policy authorization data
    iam_policy_allow = has_matching_statement(principal, 'Allow', action_to_check, resource_to_check,
                                              conditions_keys_copy, debug)
    iam_policy_deny = has_matching_statement(principal, 'Deny', action_to_check, resource_to_check,
                                             conditions_keys_copy, debug)

    # Knock out deny cases
    if iam_policy_deny or rp_result == ResourcePolicyEvalResult.DENY_MATCH:
        return False
    if pb_deny is not None and pb_deny:
        return False

    # From here, a tangled web of scenarios based on resource ownership and service
    if arns.get_account_id(principal.arn) == resource_owner:
        if arns.get_service(resource_to_check) in ('iam', 'kms'):  # TODO: tuple or list?
            # IAM or KMS, the resource policy has to match too
            if rp_result != ResourcePolicyEvalResult.NO_MATCH and ((iam_policy_allow and (pb_allow is None or pb_allow)) or rp_result == ResourcePolicyEvalResult.NODE_MATCH):
                return True
            return False
        # Otherwise, either the principal's policies or the resource policy need to match
        if (iam_policy_allow and (pb_allow is None or pb_allow)) or rp_result == ResourcePolicyEvalResult.NODE_MATCH:
            return True
        return False
    else:
        # Separate accounts, the principal policies and the resource policy must allow it
        if (iam_policy_allow and (pb_allow is None or pb_allow)) and rp_result != ResourcePolicyEvalResult.NO_MATCH:
            return True
        return False


def simulation_api_check_authorization(iamclient, principal: Node, action_to_check: str, resource_to_check: str,
                                       condition_keys_to_check: dict, debug: bool = False) -> bool:
    """DO NOT USE THIS FUNCTION, IT WILL ONLY THROW A NotImplementedError."""

    raise NotImplementedError('Principal Mapper only supports local authorization checks, and will continue to only '
                              'perform local authorization checks for the forseeable future.')
