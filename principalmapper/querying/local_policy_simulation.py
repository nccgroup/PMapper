"""Utility code for the querying module: creates functions for simulating the authorization of principals making
API calls to AWS."""

import datetime as dt
import dateutil.parser as dup
from enum import Enum
from typing import List, Dict, Optional, Union
import re

from principalmapper.common.nodes import Node
from principalmapper.util.debug_print import dprint
from principalmapper.util import arns


def has_matching_statement(principal: Node, effect_value: str, action_to_check: str,
                           resource_to_check: str, condition_keys_to_check: dict, debug: bool = False) -> bool:
    """Locally determine if a node's attached policies has at least one matching statement with the given effect. This
    is the meat of the local policy evaluation.
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
                continue  # cut early

            # if action is good, check resource
            if 'Resource' in statement:
                for resource in _listify_string(statement['Resource']):
                    if _matches_after_expansion(resource_to_check, resource, condition_keys_to_check, debug=debug):
                        matches_resource = True
                        break
            elif 'NotResource' in statement:  # 'NotResource' in statement
                matches_resource = True
                for notresource in _listify_string(statement['NotResource']):
                    if _matches_after_expansion(resource_to_check, notresource, condition_keys_to_check, debug=debug):
                        matches_resource = False
                        break
            else:
                matches_resource = True  # TODO: examine validity of not using a Resource/NotResource field (trust docs)
            if not matches_resource:
                continue  # cut early

            # if resource is good, check condition
            if 'Condition' in statement:
                matches_condition = _get_condition_match(statement['Condition'], condition_keys_to_check, debug)
            else:
                matches_condition = True

            if matches_action and matches_resource and matches_condition:
                return True

    return False


def _get_condition_match(condition: Dict[str, Dict[str, Union[str, List]]], context: Dict, debug: bool = False) -> bool:
    """
    Internal method. It digs through Null, Bool, DateX, NumericX, StringX conditions and returns false if any of
    them don't match what the context has.

    Also handles ForAnyValue and ForAllValues

    See: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
    """
    for block in condition.keys():
        dprint(debug, 'Testing condition field: {}'.format(block))
        # Start by handling ...IfExists
        # If our passed context doesn't have the condition key, we can skip since it doesn't exist
        if block.endswith('IfExists'):
            can_skip = True
            for policy_context_key in condition[block]:
                if policy_context_key in context.keys():
                    can_skip = False
                    break

            if can_skip:
                continue

        # String operators
        if 'String' in block:
            # string comparison after expansion
            pass

        if 'Numeric' in block:
            # convert string to int and compare (floats allowed? how to handle?)
            pass

        if 'Date' in block:
            # need the datetime and dateutil module to do this, do everything in UTC where undefined
            if block.startswith('ForAllValues:'):
                # fail to match match unless all of the provided context values match
                for policy_key in condition[block]:
                    if policy_key in context.keys():
                        for context_value in _listify_string(context[policy_key]):
                            if context_value != '':
                                if not _get_date_match(block, policy_key, condition[block][policy_key], context, debug):
                                    return False
            elif block.startswith('ForAnyValue:'):
                # match if at least one of the provided context values match
                no_match = True
                for policy_key in condition[block]:
                    if policy_key in context.keys():
                        for context_value in _listify_string(context[policy_key]):
                            if context_value != '':
                                if _get_date_match(block, policy_key, condition[block][policy_key], context, debug):
                                    no_match = False
                if no_match:
                    return False
            else:
                for policy_context_key in condition[block]:
                    if not _get_date_match(block, policy_context_key, condition[block][policy_context_key], context,
                                           debug):
                        return False

        if 'Bool' in block:
            # straight string comparison
            pass

        if 'BinaryEquals' in block:
            # straight string comparison
            pass

        if 'IpAddress' in block:
            # need ipaddress module, use ipaddress.ip_address in <ipaddress.ip_network obj>
            pass

        if 'Arn' in block:
            # string comparison after expansion
            if block.startswith('ForAllValues:'):
                # fail to match match unless all of the provided context values match
                for policy_key in condition[block]:
                    if policy_key in context.keys():
                        for context_value in _listify_string(context[policy_key]):
                            if context_value != '':
                                if not _get_arn_match(block, policy_key, condition[block][policy_key], context, debug):
                                    return False
            elif block.startswith('ForAnyValue:'):
                # match if at least one of the provided context values match
                no_match = True
                for policy_key in condition[block]:
                    if policy_key in context.keys():
                        for context_value in _listify_string(context[policy_key]):
                            if context_value != '':
                                if _get_arn_match(block, policy_key, condition[block][policy_key], context, debug):
                                    no_match = False
                if no_match:
                    return False
            else:
                for policy_context_key in condition[block]:
                    if not _get_arn_match(block, policy_context_key, condition[block][policy_context_key], context,
                                          debug):
                        return False

        # handle Null, ForAllValues:Null, ForAnyValue:Null
        if 'Null' in block:
            if block.startswith('ForAllValues:'):
                # fail to match match unless all of the provided context values match
                for policy_key in condition[block]:
                    if policy_key in context.keys():
                        for context_value in _listify_string(context[policy_key]):
                            if context_value != '':
                                if not _get_null_match(policy_key, condition[block][policy_key], context, debug):
                                    return False
            elif block.startswith('ForAnyValue:'):
                # match if at least one of the provided context values match
                no_match = True
                for policy_key in condition[block]:
                    if policy_key in context.keys():
                        for context_value in _listify_string(context[policy_key]):
                            if context_value != '':
                                if _get_null_match(policy_key, condition[block][policy_key], context, debug):
                                    no_match = False
                if no_match:
                    return False
            else:
                for policy_context_key in condition[block]:
                    if not _get_null_match(policy_context_key, condition[block][policy_context_key], context, debug):
                        return False

    return True


def _get_date_match(block: str, policy_key: str, policy_value: Union[str, List[str]], context: dict,
                    debug: bool = False):
    """Helper method for dealing with Date* conditions: DateEquals, DateNotEquals, DateGreaterThan,
    DateGreaterThanEquals, DateLessThan, DateLessThanEquals.

    Parses values by distinguishing between epoch values and ISO 8601/RFC 3339 datetimestamps. Assumes
    the timezone is UTC when not specified.
    """
    dprint(debug, 'Checking {} for value {} with context {}, condition element {}'.format(
        policy_key, policy_value, context, block
    ))

    for value in _listify_string(policy_value):
        value_dt = _convert_timestamp_to_datetime_obj(value)
        if block == 'DateEquals':
            if policy_key not in context:
                return False
            for context_value in _listify_string(context[policy_key]):
                context_value_dt = _convert_timestamp_to_datetime_obj(context_value)
                if value_dt == context_value_dt:
                    return True
            return False


def _convert_timestamp_to_datetime_obj(timestamp: str):
    """Helper method for the helper method: converts string to datetime object"""
    if '-' in timestamp:  # policy simulator behavior: datetimestamps need dashes, even though ISO 8601 doesn't (?)
        # parse as ISO 8601/RFC 3339
        result = dup.parse(timestamp)
        if result.tzinfo is None:
            result.replace(tzinfo=dt.timezone.utc)
        return result
    else:
        # parse as epoch timestamp
        return dt.datetime.fromtimestamp(float(timestamp), dt.timezone.utc)  # TODO: concern around float imprecision


def _get_arn_match(block: str, policy_key: str, policy_value: Union[str, List[str]], context: dict,
                   debug: bool = False):
    """Helper method for dealing with Arn* conditions: ArnEquals, ArnLike, ArnNotEquals, ArnNotLike"""
    dprint(debug, 'Checking {} for value {} with context {}, condition element {}'.format(
        policy_key, policy_value, context, block
    ))

    for value in _listify_string(policy_value):
        if 'Not' in block:
            if policy_key not in context:
                return True  # policy simulator behavior: returns Allowed when context is null for given key in ArnNot*
            for context_value in _listify_string(context[policy_key]):
                if not arns.validate_arn(context_value):
                    return False  # policy simulator behavior: reject if provided value isn't a legit ARN
                if _matches_after_expansion(context_value, value, debug=debug):
                    return False
            return True
        else:
            if policy_key not in context:
                return False
            for context_value in _listify_string(context[policy_key]):
                if not arns.validate_arn(context_value):
                    continue  # skip invalid arns
                if _matches_after_expansion(context_value, value, debug=debug):
                    return True
            return False


def _get_null_match(policy_key: str, policy_value: Union[str, List[str]], context: Dict, debug: bool = False) -> bool:
    """Helper method for dealing with Null conditions"""
    dprint(debug, 'Checking {} for value {} with context {}'.format(policy_key, policy_value, context))
    for value in _listify_string(policy_value):
        if value == 'true':  # key is expected not to be in context, or empty
            if policy_key not in context or context[policy_key] == '':
                return True
        else:  # key is expected to be in the context with a non-empty value
            if policy_key in context and context[policy_key] != '':
                return True
    return False


def resource_policy_has_matching_statement_for_principal(principal: Node, resource_policy: dict, effect_value: str,
                                                         action_to_check: str, resource_to_check: str,
                                                         condition_keys_to_check: dict, debug: bool = False) -> bool:
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
        matches_condition = True  # TODO: handle this in local evaluation

        if matches_principal and matches_action and matches_resource and matches_condition:
            return True

    return False


def resource_policy_matching_statements(node_or_service: Union[Node, str], resource_policy: dict,
                                        action_to_check: str, resource_to_check: str, condition_keys_to_check: dict,
                                        debug: bool = False) -> list:
    """Returns if a resource policy has a matching statement for a given service (ec2.amazonaws.com for example)."""

    dprint(debug, 'local resource policy check - service: {}, action: {}, resource: {}, conditions: {}, '
                  'resource_policy: {}'.format(node_or_service, action_to_check, resource_to_check,
                                               condition_keys_to_check, resource_policy))

    results = []

    for statement in _listify_dictionary(resource_policy['Statement']):
        matches_principal, matches_action, matches_resource, matches_condition = False, False, False, False
        if 'Principal' in statement:  # should be a dictionary
            if isinstance(node_or_service, Node):
                if 'AWS' in statement['Principal']:
                    if _principal_matches_in_statement(node_or_service, _listify_string(statement['Principal']['AWS'])):
                        matches_principal = True
            else:
                if 'Service' in statement['Principal']:
                    if node_or_service in _listify_string(statement['Principal']['Service']):
                        matches_principal = True
        else:  # 'NotPrincipal' in statement:
            matches_principal = True
            if isinstance(node_or_service, Node):
                if 'AWS' in statement['Principal']:
                    if _principal_matches_in_statement(node_or_service, _listify_string(statement['Principal']['AWS'])):
                        matches_principal = False
            else:
                if 'Service' in statement['NotPrincipal']:
                    if node_or_service in _listify_string(statement['NotPrincipal']['Service']):
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
            results.append(statement)

    return results


class ResourcePolicyEvalResult(Enum):
    """For resource policy evaluation, we want to return a result for a few different potential set of results:

    1. No match - depends on caller's permissions depending on the service
    2. Deny statement match - node or root as Principal (explicit deny)
    3. Caller in same account as resource: root Principal only
    4. Caller in any account: node Principal matched
    5. Caller in different account as resource: root Principal matched
    6. Service matches
    """
    NO_MATCH = 1
    DENY_MATCH = 2
    ROOT_MATCH = 3
    NODE_MATCH = 4
    DIFF_ACCOUNT_MATCH = 5
    SERVICE_MATCH = 6


def resource_policy_authorization(node_or_service: Union[Node, str], resource_owner: str, resource_policy: dict,
                                  action_to_check: str, resource_to_check: str, condition_keys_to_check: dict,
                                  debug: bool) -> ResourcePolicyEvalResult:
    """Returns a ResourcePolicyEvalResult for a given request, based on the resource policy."""
    dprint(debug, "Local resource policy authorization check: Principal {}, Action {}, Resource {}, Condition Keys {}, "
                  "Resource Owner {}".format(node_or_service, action_to_check, resource_to_check,
                                             condition_keys_to_check, resource_owner))

    matching_statements = resource_policy_matching_statements(node_or_service, resource_policy, action_to_check,
                                                              resource_to_check, condition_keys_to_check, debug)
    if len(matching_statements) == 0:
        return ResourcePolicyEvalResult.NO_MATCH

    # handle nodes (IAM Users or Roles)
    if isinstance(node_or_service, Node):
        # if in a different account, check for denies and wrap it up
        if arns.get_account_id(node_or_service.arn) != resource_owner:
            for statement in matching_statements:
                if statement['Effect'] == 'Deny':
                    return ResourcePolicyEvalResult.DENY_MATCH
            return ResourcePolicyEvalResult.DIFF_ACCOUNT_MATCH

        else:
            # messy part: find denies, then determine if we send back ROOT or NODE match
            for statement in matching_statements:
                if statement['Effect'] == 'Deny':
                    return ResourcePolicyEvalResult.DENY_MATCH

            node_match = False
            for statement in matching_statements:
                if 'NotPrincipal' in statement:
                    # NotPrincipal means a node match (tested with S3)
                    node_match = True
                else:
                    for principal in _listify_string(statement['Principal']):
                        if node_or_service.arn == principal:
                            node_match = True
                        if node_or_service.id_value == principal:
                            node_match = True  # 'AIDA.*' and co. can match here

            if node_match:
                return ResourcePolicyEvalResult.NODE_MATCH
            else:
                return ResourcePolicyEvalResult.ROOT_MATCH

    else:
        return ResourcePolicyEvalResult.SERVICE_MATCH


def _principal_matches_in_statement(principal: Node, aws_principal_field: list):
    """Helper function for locally determining a principal matches a resource policy's statement"""
    for value in aws_principal_field:
        if principal.arn == value:
            return True
        elif principal.id_value == value:
            return True
        elif arns.get_account_id(principal.arn) == value:
            return True
        else:
            principal_root_str = 'arn:{}:iam::{}:root'.format(arns.get_partition(principal.arn),
                                                              arns.get_account_id(principal.arn))
            if principal_root_str == value:
                return True
    return False


def policies_include_matching_allow_action(principal: Node, action_to_check: str, debug: bool = False) -> bool:
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
                return True  # so broad that we'd need to simulate to make sure
    return False


def _matches_after_expansion(string_to_check: str, string_to_check_against: str,
                             condition_keys: Optional[dict] = None, debug: bool = False) -> bool:
    """Helper function that checks the string_to_check against string_to_check_against.

    Handles matching with respect to wildcards, variables.
    """
    dprint(debug, 'Checking for post-expansion match.\n   string to check: {}\n   '.format(string_to_check) +
           'string to check against: {}\n'.format(string_to_check_against) +
           '   condition_keys: {}'.format(condition_keys))

    # regexify string_to_check_against
    # handles use of ${} var substitution, wildcards (*), and periods (.)
    copy_string = string_to_check_against

    if condition_keys is not None:
        for k, v in condition_keys.items():
            full_key = '${' + k + '}'
            copy_string = copy_string.replace(full_key, v)

    pattern_string = copy_string \
        .replace(".", "\\.") \
        .replace("*", ".*") \
        .replace("?", ".") \
        .replace("$", "\\$") \
        .replace("^", "\\^")
    pattern_string = "^{}$".format(pattern_string)
    dprint(debug, '   post-processed pattern_string: {}'.format(pattern_string))

    # return result of match
    return re.match(pattern_string, string_to_check, flags=re.IGNORECASE) is not None


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
