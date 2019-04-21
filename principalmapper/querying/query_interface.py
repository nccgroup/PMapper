"""Code for querying a graph about specific access to actions and resources in AWS"""

from typing import List, Dict, Optional, Union
import re

from principalmapper.common.nodes import Node
from principalmapper.util.debug_print import dprint
from principalmapper.util import arns


def is_authorized_for(iamclient, principal: Node, action_to_check: str, resource_to_check: str,
                      condition_keys_to_check: dict, validate_with_api: bool = True,
                      debug: bool = False) -> bool:
    """Determine if a node is authorized to make an API call. It will either attempt a local evaluation of the
    principal's policies or call iam:SimulatePrincipalPolicy depending on if validate_with_api is set.

     """
    dprint(debug, 'testing for matching statement, principal: {}, action: {}, resource: {}, conditions: {}'.format(
        principal.arn,
        action_to_check,
        resource_to_check,
        condition_keys_to_check
    ))

    if validate_with_api:
        if _policies_include_matching_allow_action(principal, action_to_check, debug):
            pass
        # TODO: uncomment below when it is ready
        # return is_authorized_per_simulation(iamclient, principal, action_to_check, resource_to_check,
        #                                     condition_keys_to_check, debug)

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
    return False  # TODO: finish out


def has_matching_statement(principal: Node, effect_value: str, action_to_check: str,
                           resource_to_check: str, condition_keys_to_check: dict, debug: bool = False) -> bool:
    """Locally determine if a node's attached policies has at least one matching statement with an Allow effect.

    Assumes the action/resource/condition key parameters do not use wildcards.

    Does not replace full evaluation with iam:SimulatePrincipalPolicy, but can save time/API calls since there must be
    at least one matching Allow statement when you make an API call.
    """
    dprint(debug, 'local test for matching statement, principal: {}, effect: {}, action: {}, resource: {}, '
           'conditions: {}'.format(
            principal.arn,
            effect_value,
            action_to_check,
            resource_to_check,
            condition_keys_to_check
            ))

    # For each policy...
    for policy in principal.attached_policies:
        # go through each policy_doc
        for statement in _listify_dictionary(policy.policy_doc['Statement']):
            if statement['Effect'] != effect_value:
                continue  # skip if effect doesn't match

            matches_action, matches_resource, matches_condition = False, False, False

            # start by checking the action
            if 'Action' in statement:
                for action in _listify_string(statement['Action']):
                    matches_action = _matches_after_expansion(action_to_check, action, debug=debug)
                    break
            else:  # 'NotAction' in statement
                matches_action = True
                for notaction in _listify_string(statement['NotAction']):
                    if _matches_after_expansion(action_to_check, notaction, debug=debug):
                        matches_action = False
                        break  # finish looping
            if not matches_action:
                continue

            # if action is good, check resource
            if 'Resource' in statement:
                for resource in _listify_string(statement['Resource']):
                    if _matches_after_expansion(resource_to_check, resource, debug=debug):
                        matches_resource = True
                        break
            else:  # 'NotResource' in statement
                matches_resource = True
                for notresource in _listify_string(statement['NotResource']):
                    if _matches_after_expansion(resource_to_check, notresource, debug=debug):
                        matches_resource = False
                        break

            # if resource is good, check condition
            matches_condition = True  # TODO: implement local condition check in policy/statement loop

            if matches_action and matches_resource and matches_condition:
                return True

    return False


def resource_policy_has_matching_statement(principal: Node, resource_policy: dict, effect_value: str,
                                           action_to_check: str, resource_to_check: str, condition_keys_to_check: dict,
                                           debug: bool = False):
    """Locally determine if a node is permitted by a resource policy for a given action/resource/condition"""
    dprint(debug, 'local resource policy check - principal: {}, effect: {}, action: {}, resource: {}, conditions: {}, '
                  'resource_policy: {}'.format(principal.arn, effect_value, action_to_check, resource_to_check,
                                               condition_keys_to_check, resource_policy))

    for statement in _listify_dictionary(resource_policy['Statement']):
        if statement['Effect'] != effect_value:
            continue
        matches_principal, matches_action, matches_resource, matches_condition = False, False, False, False
        if 'Principal' in statement:  # should be a dictionary
            if 'AWS' in statement['Principal']:
                if _principal_matches_in_statement(principal, _listify_string(statement['Principal']['AWS'])):
                    matches_principal = True
        else:  # 'NotPrincipal' in statement:
            matches_principal = True
            if 'AWS' in statement['NotPrincipal']:
                if _principal_matches_in_statement(principal, _listify_string(statement['NotPrincipal']['AWS'])):
                    matches_principal = False

        if not matches_principal:
            continue

        # if principal is good, proceed to check the Action
        if 'Action' in statement:
            for action in _listify_string(statement['Action']):
                matches_action = _matches_after_expansion(action_to_check, action, debug=debug)
                break
        else:  # 'NotAction' in statement
            matches_action = True
            for notaction in _listify_string(statement['NotAction']):
                if _matches_after_expansion(action_to_check, notaction, debug=debug):
                    matches_action = False
                    break  # finish looping
        if not matches_action:
            continue

        # if action is good, proceed to check resource
        if 'Resource' in statement:
            for resource in _listify_string(statement['Resource']):
                if _matches_after_expansion(resource_to_check, resource, debug=debug):
                    matches_resource = True
                    break
        elif 'NotResource' in statement:
            matches_resource = True
            for notresource in _listify_string(statement['NotResource']):
                if _matches_after_expansion(resource_to_check, notresource, debug=debug):
                    matches_resource = False
                    break
        else:  # no resource element (seen in IAM role trust policies), treat as a match
            matches_resource = True

        # if resource is good, check condition
        matches_condition = True  # TODO: implement local condition check in policy/statement loop

        if matches_principal and matches_action and matches_resource and matches_condition:
            return True

    return False


def _principal_matches_in_statement(principal: Node, aws_principal_field: list):
    """Helper function for locally determining a principal matches a resource policy's statement"""
    for value in aws_principal_field:
        if principal.arn == value:
            return True
        elif arns.get_account_id(principal.arn) == value:
            return True
        else:
            principal_root_str = 'arn:{}:iam::{}:root'.format(arns.get_partition(principal.arn),
                                                              arns.get_account_id(principal.arn))
            if principal_root_str == value:
                return True
    return False


def _policies_include_matching_allow_action(principal: Node, action_to_check: str, debug: bool = False) -> bool:
    """Helper function for online-testing. Does a 'light' scan of a principal's policies to determine if any of
    their statements have an Allow statement with a matching action. Helps reduce unecessary API calls to
    iam:SimulatePrincipalPolicy.
    """
    dprint(debug, 'optimization check, determine if {} could even possibly call {}'.format(
        principal.arn, action_to_check
    ))
    for policy in principal.attached_policies:
        for statement in _listify_dictionary(policy.policy_doc['Statement']):
            if statement['Effect'] != 'Allow':
                continue
            if 'Action' in statement:
                for action in _listify_string(statement['Action']):
                    if _matches_after_expansion(action_to_check, action, debug=debug):
                        return True
            else:  # 'NotAction' in statement
                matches_action = True
                for notaction in _listify_string(statement['NotAction']):
                    if _matches_after_expansion(action_to_check, notaction, debug=debug):
                        matches_action = False
                        break
                if matches_action:
                    return True
    return False


def _matches_after_expansion(string_to_check: str, string_to_check_against: str,
                             condition_keys: Optional[dict] = None, debug: bool = False) -> bool:
    """Helper function that checks the string_to_check against string_to_check_against.

    Handles matching with respect to wildcards.

    TODO: Include handling of condition key substitution
    """
    dprint(debug, 'Checking for post-expansion match.\n   string to check: {}\n   '.format(string_to_check) +
                  'string to check against: {}\n'.format(string_to_check_against) +
                  '   condition_keys: {}'.format(condition_keys))

    # regexify string_to_check_against
    # handles use of ${} var substitution, wildcards (*), and periods (.)
    # TODO: skip the checks for ${<var>} here and replace using passed condition keys
    pattern_string = string_to_check_against\
        .replace("{", "\\{")\
        .replace("}", "\\}")\
        .replace("$", "\\$")\
        .replace(".", "\\.")\
        .replace("*", ".*")
    pattern_string = "^{}$".format(pattern_string)
    dprint(debug, '   post-processed pattern_string: {}'.format(pattern_string))

    # return result of match
    return re.match(pattern_string, string_to_check) is not None


def _listify_dictionary(target_object: Union[List[Dict], Dict]) -> List[Dict]:
    """Helper function that takes a dictionary and returns it wrapped in a list"""
    if isinstance(target_object, list):
        return target_object
    else:
        return [target_object]


def _listify_string(target_object: Union[List[str], str]) -> List[str]:
    """Helper function that takes a string and returns it wrapped in a list"""
    if isinstance(target_object, list):
        return target_object
    else:
        return [target_object]
