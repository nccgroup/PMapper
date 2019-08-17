"""Code for querying a graph about specific access to actions and resources in AWS"""

import datetime as dt

from principalmapper.common.graphs import Graph
from principalmapper.querying import query_utils
from principalmapper.querying.local_policy_simulation import *
from principalmapper.querying.query_result import QueryResult


def search_authorization_for(iamclient, graph: Graph, principal: Node, action_to_check: str, resource_to_check: str,
                             condition_keys_to_check: dict, validate_with_api: bool = True,
                             debug: bool = False) -> QueryResult:
    """Determines if the passed principal, or any principals it can access, can perform a given action for a
    given resource/condition."""
    if principal.is_admin:
        return QueryResult(True, [], principal)

    if is_authorized_for(iamclient, principal, action_to_check, resource_to_check, condition_keys_to_check,
                         validate_with_api, debug):
        return QueryResult(True, [], principal)

    for edge_list in query_utils.get_search_list(graph, principal):
        if is_authorized_for(iamclient, edge_list[-1].destination, action_to_check, resource_to_check,
                             condition_keys_to_check, validate_with_api, debug):
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
        result['aws:CurrentTime'] = dt.datetime.utcnow().isoformat()

    if 'aws:EpochTime' not in current_keys:
        result['aws:EpochTime'] = str(round(dt.datetime.utcnow().timestamp()))

    # UserID and Username: aws:userid and aws:username
    # TODO: Double-check how roles handle aws:username, IIRC it's not filled in
    if 'aws:userid' not in current_keys:
        result['aws:userid'] = principal.id_value

    if ':user/' in principal.arn and 'aws:username' not in current_keys:
        result['aws:username'] = principal.searchable_name().split('/')[1]

    return result


def is_authorized_for(iamclient, principal: Node, action_to_check: str, resource_to_check: str,
                      condition_keys_to_check: dict, validate_with_api: bool = False,
                      debug: bool = False) -> bool:
    """Determine if a node is authorized to make an API call. It will either attempt a local evaluation of the
    principal's policies or call iam:SimulatePrincipalPolicy depending on if validate_with_api is set.

    NOTE: this will add condition keys that it can infer, assuming they're not set already, such as aws:username or
    aws:userid.
    """
    dprint(debug, 'testing for matching statement, principal: {}, action: {}, resource: {}, conditions: {}'.format(
        principal.arn,
        action_to_check,
        resource_to_check,
        condition_keys_to_check
    ))

    condition_keys_to_check.update(_infer_condition_keys(principal, condition_keys_to_check))

    if validate_with_api:
        raise NotImplementedError('Simulation with the API is not implemented yet.')

    # must have a matching Allow statement, otherwise it's an implicit deny
    if not has_matching_statement(principal, 'Allow', action_to_check, resource_to_check,
                                  condition_keys_to_check, debug):
        return False

    # must not have a matching Deny statement, otherwise it's an explicit deny
    return not has_matching_statement(principal, 'Deny', action_to_check, resource_to_check,
                                      condition_keys_to_check, debug)


def is_authorized_per_simulation(iamclient, principal: Node, action_to_check: str, resource_to_check: str,
                                 condition_keys_to_check: dict, debug: bool = False) -> bool:
    """Determine if a node is authorized for an API call via iam:SimulatePrincipalPolicy."""
    dprint(debug, 'calling iam:SimulatePrincipalPolicy with principal: {}, action: {}, resource: {}, conditions: {}'
           .format(principal.arn, action_to_check, resource_to_check, condition_keys_to_check))
    raise NotImplementedError('Testing using the Simulation API is not available yet.')
