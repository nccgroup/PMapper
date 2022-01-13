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
from typing import Dict, Tuple, Any, Union

from principalmapper.common import Graph, Edge
from principalmapper.querying import query_utils
from principalmapper.querying.local_policy_simulation import *
from principalmapper.querying.query_result import QueryResult
from principalmapper.util import arns


logger = logging.getLogger(__name__)
_UODict = Union[Dict[str, Any], CaseInsensitiveDict]


def search_authorization_for(graph: Graph, principal: Node, action_to_check: str, resource_to_check: str,
                             condition_keys_to_check: _UODict) -> QueryResult:
    """Determines if the passed principal, or any principals it can access, can perform a given action for a
    given resource/condition."""

    if local_check_authorization(principal, action_to_check, resource_to_check, condition_keys_to_check):
        return QueryResult(True, [], principal)

    # Invoke special-case if admin node is not directly authorized to call the given action for the given resource
    if principal.is_admin:
        return QueryResult(True, principal, principal)

    for edge_list in query_utils.get_search_list(graph, principal):
        if local_check_authorization(edge_list[-1].destination, action_to_check, resource_to_check,
                                     condition_keys_to_check):
            return QueryResult(True, edge_list, principal)

    return QueryResult(False, [], principal)


def search_authorization_full(graph: Graph, principal: Node, action_to_check: str, resource_to_check: str,
                              condition_keys_to_check: _UODict, resource_policy: Optional[dict] = None,
                              resource_owner: Optional[str] = None, service_control_policies: List[List[Policy]] = None,
                              session_policy: Optional[dict] = None) -> QueryResult:
    """Determines if the passed principal, or any principals it can access, can perform a given action for a
    given resource/condition. Handles an optional resource policy, an optional SCP list, and an optional
    session policy. SCPs are considered in the full search list, but the session policy is discarded after checking
    if the passed principal has access (we assume it is discarded after each pivot, and that it does NOT affect
    the accessibility of the edges).

    In `local_check_authorization` we usually throw up our hands if the given principal is an admin. But, because of
    how SCPs work (even blocking the root user), we force the full search to give more accurate results. If the
    SCPs param is None, we assume no SCPs are in place and can make the same assumption as in
    `local_check_authorization`.

    If the resource_owner param is not None, and the resource_owner param is None, the `local_check_authorization_full`
    function that gets called will throw a ValueError, so make sure the resource ownership is sorted before calling
    this method."""

    if local_check_authorization_full(principal, action_to_check, resource_to_check, condition_keys_to_check,
                                      resource_policy, resource_owner, service_control_policies, session_policy):
        return QueryResult(True, [], principal)

    if service_control_policies is None and principal.is_admin:
        return QueryResult(True, principal, principal)

    for edge_list in query_utils.get_search_list(graph, principal):
        if local_check_authorization_full(edge_list[-1].destination, action_to_check, resource_to_check, condition_keys_to_check,
                                          resource_policy, resource_owner, service_control_policies, None):
            return QueryResult(True, edge_list, principal)

    return QueryResult(False, [], principal)


def search_authorization_across_accounts(graph_scp_pairs: List[Tuple[Graph, Optional[List[List[Policy]]]]],
                                         inter_account_edges: List[Edge], principal: Node,
                                         action_to_check: str, resource_to_check: str,
                                         condition_keys_to_check: _UODict, resource_policy: Optional[dict] = None,
                                         resource_owner: Optional[str] = None,
                                         session_policy: Optional[dict] = None) -> QueryResult:
    """Determines if the passed principal, or any principals it can access, can perform a given action for a
    given resource/condition. Handles an optional resource policy, an optional SCP list, and an optional
    session policy. The session policy is discarded after checking if the passed principal has access
    (we assume it is discarded after each pivot, and that it does NOT affect the accessibility of the edges).

    In `local_check_authorization` we usually throw up our hands if the given principal is an admin. But, because of
    how SCPs work (even blocking the root user), we force the full search to give more accurate results. If the
    SCPs param is None, we assume no SCPs are in place and can make the same assumption as in
    `local_check_authorization`.

    If the resource_owner param is not None, and the resource_owner param is None, the `local_check_authorization_full`
    function that gets called will throw a ValueError, so make sure the resource ownership is sorted before calling
    this method.

    The graphs to include in the search have to be passed in tuples. The second element of the tuple is either the SCPs
    that affect that graph or None. If your graph belongs to an organization, remember that you can take the
    OrganizationTree object and produce the applicable SCPs by calling
    principalmapper.querying.query_orgs.produce_scp_list and passing the graph + org-tree objects."""

    account_id_graph_scp_pair_map = {}
    for graph_scp_pair in graph_scp_pairs:
        account_id_graph_scp_pair_map[graph_scp_pair[0].metadata['account_id']] = graph_scp_pair
    source_graph_scp_pair = account_id_graph_scp_pair_map[arns.get_account_id(principal.arn)]

    if local_check_authorization_full(principal, action_to_check, resource_to_check, condition_keys_to_check,
                                      resource_policy, resource_owner, source_graph_scp_pair[1], session_policy):
        return QueryResult(True, [], principal)

    # now we have to check cross-account scenario for admin short-circuit
    if source_graph_scp_pair[1] is None and principal.is_admin and resource_owner == arns.get_account_id(principal.arn):
        return QueryResult(True, principal, principal)

    for edge_list in query_utils.get_interaccount_search_list([x[0] for x in graph_scp_pairs], inter_account_edges, principal):
        proxy_principal = edge_list[-1].destination
        proxy_principal_scps = account_id_graph_scp_pair_map[arns.get_account_id(proxy_principal.arn)][1]
        if local_check_authorization_full(edge_list[-1].destination, action_to_check, resource_to_check, condition_keys_to_check,
                                          resource_policy, resource_owner, proxy_principal_scps, None):
            return QueryResult(True, edge_list, principal)

    return QueryResult(False, [], principal)


def _prepare_condition_context(original_dict: _UODict) -> CaseInsensitiveDict:
    """Returns a CaseInsensitiveDict with the given dictionary contents, while also performing a sanity check
    to ensure that there are no duplicate keys in the provided context."""

    if len(original_dict) != len(set([x.lower() for x in original_dict.keys()])):
        raise ValueError('Detected a duplicate context key/value pair. Ensure that there are no duplicate context '
                         'keys, case-insensitive.')

    return CaseInsensitiveDict(original_dict)


def _infer_condition_keys(principal: Node, current_keys: CaseInsensitiveDict) -> CaseInsensitiveDict:
    """Returns a dictionary with global condition context keys we can infer are set based on the input Node being
    checked. We exclude setting keys that are already set in current_keys.

    Using information from https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html

    Changes in v1.1.3:
        * Changed param current_keys type to CaseInsensitiveDict
        * Changed return type to CaseInsensitiveDict
    """

    result = CaseInsensitiveDict()

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

    # assumes API requests are made via secure channel (HTTPS)
    if 'aws:SecureTransport' not in current_keys:
        result['aws:SecureTransport'] = 'true'

    if 'aws:PrincipalAccount' not in current_keys:
        result['aws:PrincipalAccount'] = arns.get_account_id(principal.arn)

    if 'aws:PrincipalArn' not in current_keys:
        result['aws:PrincipalArn'] = principal.arn

    # NOTE: tag keys are checked for case-insensitive equality already, no worries about collisions
    for tag_key, tag_value in principal.tags.items():
        if 'aws:PrincipalTag/{}'.format(tag_key) not in current_keys:
            result['aws:PrincipalTag/{}'.format(tag_key)] = tag_value

    return result


def local_check_authorization_handling_mfa(principal: Node, action_to_check: str, resource_to_check: str,
                                           condition_keys_to_check: _UODict, resource_policy: Optional[dict] = None,
                                           resource_owner: Optional[str] = None,
                                           service_control_policy_groups: Optional[List[List[Policy]]] = None,
                                           session_policy: Optional[dict] = None) -> (bool, bool):
    """Determine if a node is authorized to make an API call. If the node is an IAM User, it will perform authorization
    checks with and without MFA enabled. It returns a (bool, bool) tuple: if the user was authorized and if MFA was
    required for the authorization.
    """

    if ':role/' in principal.arn:  # TODO: aws:MultiFactorAuthPresent pass-through?
        return local_check_authorization_full(principal, action_to_check, resource_to_check, condition_keys_to_check, resource_policy, resource_owner, service_control_policy_groups, session_policy), False

    if local_check_authorization_full(principal, action_to_check, resource_to_check, condition_keys_to_check, resource_policy, resource_owner, service_control_policy_groups, session_policy):
        return True, False

    new_condition_keys = copy.deepcopy(condition_keys_to_check)
    prepped_condition_keys = _prepare_condition_context(new_condition_keys)
    if 'aws:MultiFactorAuthAge' not in prepped_condition_keys:
        prepped_condition_keys.update({'aws:MultiFactorAuthAge': '1'})
    if 'aws:MultiFactorAuthPresent' not in prepped_condition_keys:
        prepped_condition_keys.update({'aws:MultiFactorAuthPresent': 'true'})

    if local_check_authorization_full(principal, action_to_check, resource_to_check, prepped_condition_keys, resource_policy, resource_owner, service_control_policy_groups, session_policy):
        return True, True

    return False, False


def local_check_authorization(principal: Node, action_to_check: str, resource_to_check: str,
                              condition_keys_to_check: _UODict) -> bool:
    """Determine if a node is authorized to make an API call. It will perform a local evaluation of the attached
    IAM policies to determine authorization.

    NOTE: this will add condition keys that it can infer, assuming they're not set already, such as aws:username or
    aws:userid.
    """

    conditions_keys_copy = copy.deepcopy(condition_keys_to_check)
    prepped_condition_keys = _prepare_condition_context(conditions_keys_copy)
    prepped_condition_keys.update(_infer_condition_keys(principal, prepped_condition_keys))

    logger.debug('Testing authorization for Principal: {}, Action: {}, Resource: {}, Conditions: {}'.format(
        principal.arn,
        action_to_check,
        resource_to_check,
        conditions_keys_copy
    ))

    # Handle permission boundaries if applicable
    if principal.permissions_boundary is not None:
        if policy_has_matching_statement(principal.permissions_boundary, 'Deny', action_to_check, resource_to_check,
                                         prepped_condition_keys):
            return False
        if not policy_has_matching_statement(principal.permissions_boundary, 'Allow', action_to_check, resource_to_check,
                                             prepped_condition_keys):
            return False

    # must have a matching Allow statement, otherwise it's an implicit deny
    if not has_matching_statement(principal, 'Allow', action_to_check, resource_to_check,
                                  prepped_condition_keys):
        return False

    # must not have a matching Deny statement, otherwise it's an explicit deny
    return not has_matching_statement(principal, 'Deny', action_to_check, resource_to_check,
                                      prepped_condition_keys)


def local_check_authorization_full(principal: Node, action_to_check: str, resource_to_check: str,
                                   condition_keys_to_check: _UODict, resource_policy: Optional[dict] = None,
                                   resource_owner: Optional[str] = None,
                                   service_control_policy_groups: Optional[List[List[Policy]]] = None,
                                   session_policy: Optional[dict] = None) -> bool:
    """Determine if a given node is authorized to make an API call. It will perform a full local policy evaluation,
    which includes:

    * Checking for any matching Deny statements in all policies that are given
    * Checking Organization SCPs (if given)
    * Checking the resource policy (if given)
    * Checking the principal's permission boundaries (if the caller has any attached)
    * Checking the session policy (if given)
    * Checking the principal's policies

    This will add condition keys that may be inferred, assuming they are not already set, such as the
    aws:username or aws:userid keys.

    If the resource_policy param is not None but the resource_owner is None, this raises a ValueError, so that must
    be sorted beforehand by any code calling this function."""

    if resource_policy is not None and resource_owner is None:
        raise ValueError('Must specify the AWS Account ID of the owner of the resource when specifying a resource policy')

    conditions_keys_copy = copy.deepcopy(condition_keys_to_check)
    prepped_condition_keys = _prepare_condition_context(conditions_keys_copy)
    prepped_condition_keys.update(_infer_condition_keys(principal, prepped_condition_keys))

    is_not_service_linked_role = not _check_if_service_linked_role(principal)

    logger.debug(
        'Testing authorization for: principal: {}, action: {}, resource: {}, conditions: {}, Resource Policy: {}, SCPs: {}, Session Policy: {}'.format(
            principal.arn,
            action_to_check,
            resource_to_check,
            conditions_keys_copy,
            resource_policy,
            service_control_policy_groups,
            session_policy
        ))

    # Check all policies for a matching deny
    for policy in principal.attached_policies:
        if policy_has_matching_statement(policy, 'Deny', action_to_check, resource_to_check, prepped_condition_keys):
            logger.debug('Explicit Deny: Principal\'s attached policies.')
            return False

    for iam_group in principal.group_memberships:
        for policy in iam_group.attached_policies:
            if policy_has_matching_statement(policy, 'Deny', action_to_check, resource_to_check, prepped_condition_keys):
                logger.debug('Explicit Deny: Principal\'s IAM Group policies')
                return False

    if service_control_policy_groups is not None and is_not_service_linked_role:
        for service_control_policy_group in service_control_policy_groups:
            for service_control_policy in service_control_policy_group:
                if policy_has_matching_statement(service_control_policy, 'Deny', action_to_check, resource_to_check, prepped_condition_keys):
                    logger.debug('Explicit Deny: SCPs')
                    return False

    if resource_policy is not None:
        rp_matching_statements = resource_policy_matching_statements(principal, resource_policy, action_to_check, resource_to_check, prepped_condition_keys)
        for statement in rp_matching_statements:
            if statement['Effect'] == 'Deny':
                logger.debug('Explicit Deny: Resource Policy')
                return False

    if session_policy is not None:
        if policy_has_matching_statement(session_policy, 'Deny', action_to_check, resource_to_check, prepped_condition_keys):
            logger.debug('Explict Deny: Session policy')
            return False

    if principal.permissions_boundary is not None:
        if policy_has_matching_statement(principal.permissions_boundary, 'Deny', action_to_check, resource_to_check, prepped_condition_keys):
            logger.debug('Explicit Deny: Permission Boundary')
            return False

    # Check SCPs
    if service_control_policy_groups is not None and is_not_service_linked_role:
        for service_control_policy_group in service_control_policy_groups:
            # For every group of SCPs (policies attached to the ancestors of the account and the current account), the
            # group of SCPs have to have a matching allow statement
            scp_group_result = False
            for service_control_policy in service_control_policy_group:
                if policy_has_matching_statement(service_control_policy, 'Allow', action_to_check, resource_to_check,
                                                 prepped_condition_keys):
                    scp_group_result = True
                    break

            if not scp_group_result:
                logger.debug('Implicit Deny: SCP group')
                return False

    # Check resource policy
    if resource_policy is not None:
        rp_auth_result = resource_policy_authorization(principal, resource_owner, resource_policy, action_to_check, resource_to_check, prepped_condition_keys)
        if arns.get_account_id(principal.arn) == resource_owner:
            # resource is owned by account
            if arns.get_service(resource_to_check) in ('iam', 'kms'):  # TODO: tuple or list?
                # IAM and KMS require the trust/key policy to match
                if rp_auth_result is not ResourcePolicyEvalResult.NODE_MATCH and rp_auth_result is not ResourcePolicyEvalResult.ROOT_MATCH:
                    logger.debug('IAM/KMS Denial: RP must authorize even with same account')
                    return False
            if rp_auth_result is ResourcePolicyEvalResult.NODE_MATCH:
                # If the specific IAM User/Role is given in the resource policy's Principal element and from the same
                # account as the resource, we're done since we've already done deny-checks and the permission boundaries
                # + session policy + principal policies aren't necessary to grant authorization
                logger.debug('RP approval: skip further evaluation')
                return True
        else:
            # resource is owned by another account
            if rp_auth_result is ResourcePolicyEvalResult.NO_MATCH:
                logger.debug('Cross-Account authorization denied')
                return False

    # Check permission boundary
    if principal.permissions_boundary is not None:
        if not policy_has_matching_statement(principal.permissions_boundary, 'Allow', action_to_check, resource_to_check, prepped_condition_keys):
            logger.debug('Implicit Deny: Permission Boundary')
            return False

    # Check session policy
    if session_policy is not None:
        if not policy_has_matching_statement(session_policy, 'Allow', action_to_check, resource_to_check, prepped_condition_keys):
            logger.debug('Implicit Deny: Session Policy')
            return False

    # Check principal's policies
    for policy in principal.attached_policies:
        if policy_has_matching_statement(policy, 'Allow', action_to_check, resource_to_check, prepped_condition_keys):
            return True  # already did Deny statement checks, so we're done

    # Check principal's IAM Groups policies
    for iam_group in principal.group_memberships:
        for policy in iam_group.attached_policies:
            if policy_has_matching_statement(policy, 'Allow', action_to_check, resource_to_check, prepped_condition_keys):
                return True  # already did Deny statement checks, so we're done

    logger.debug('Implicit Deny: Principal\'s Attached Policies')
    return False


def _check_if_service_linked_role(principal: Node) -> bool:
    """Given a Node, determine if it should be treated as a service-linked role. This affects SCP policy decisions as
    described in
    https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html#not-restricted-by-scp"""

    if ':role/' in principal.arn:
        role_name = principal.arn.split('/')[-1]
        return role_name.startswith('AWSServiceRoleFor')
    return False


def simulation_api_check_authorization(iamclient, principal: Node, action_to_check: str, resource_to_check: str,
                                       condition_keys_to_check: dict) -> bool:
    """DO NOT USE THIS FUNCTION, IT WILL ONLY THROW A NotImplementedError."""

    raise NotImplementedError('Principal Mapper only supports local authorization checks, and will continue to only '
                              'perform local authorization checks for the forseeable future.')
