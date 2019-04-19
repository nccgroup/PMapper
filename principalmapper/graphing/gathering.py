"""Python code for gathering IAM-related information from an AWS account"""

import io
import os

import botocore.session
from principalmapper.common.groups import Group
from principalmapper.common.graphs import Graph
from principalmapper.common.nodes import Node
from principalmapper.common.policies import Policy
from principalmapper.util import arns
from principalmapper.util.debug_print import dprint
from typing import List
from typing import Optional


def create_graph(session: botocore.session.Session, metadata: dict, output: io.StringIO = os.devnull,
                 debug=False) -> Graph:
    """Creates a list of Node objects to use for building a Graph.

    Parameter `metadata` must be a valid dictionary with 'account_id' and 'pmapper_version' correctly filled in
    Information about the graph as it's built will be written to parameter `output`
    """
    iamclient = session.create_client('iam')

    # Gather users and roles, generating a Node per user and per role
    nodes_result = get_unfilled_nodes(iamclient, output, debug)

    # Gather groups from current list of nodes (users), generate Group objects, attach to nodes in-flight
    groups_result = get_unfilled_groups(iamclient, nodes_result, output, debug)

    # Resolve all policies, generate Policy objects, attach to all groups and nodes
    policies_result = get_policies_and_fill_out(iamclient, nodes_result, groups_result, output, debug)

    # Determine which nodes are admins and update node objects
    # TODO: search for admins

    # Generate edges, generate Edge objects
    edges_result = []  # TODO: get edges

    return Graph(nodes_result, edges_result, policies_result, groups_result, metadata)


def get_unfilled_nodes(iamclient, output: io.StringIO = os.devnull, debug=False) -> List[Node]:
    """Using an IAM.Client object, return a list of Node object for each IAM user and role in an account.

    Does not set Group or Policy objects. Those have to be filled in later.

    Writes high-level information on progress to the output file
    """
    result = []
    # Get users, paginating results, still need to handle policies + group memberships + is_admin
    output.write("Obtaining IAM users in account\n")
    user_paginator = iamclient.get_paginator('list_users')
    for page in user_paginator.paginate(PaginationConfig={'PageSize': 25}):
        dprint(debug, 'list_users page: {}'.format(page))
        for user in page['Users']:
            result.append(Node(
                arn=user['Arn'],
                attached_policies=[],
                group_memberships=[],
                trust_policy=None,
                num_access_keys=0,
                active_password='PasswordLastUsed' in user,
                is_admin=False
            ))
            dprint(debug, 'Adding Node for user ' + user['Arn'])

    # Get roles, paginating results, still need to handle policies + is_admin
    output.write("Obtaining IAM roles in account\n")
    role_paginator = iamclient.get_paginator('list_roles')
    for page in role_paginator.paginate(PaginationConfig={'PageSize': 25}):
        dprint(debug, 'list_roles page: {}'.format(page))
        for role in page['Roles']:
            result.append(Node(
                arn=role['Arn'],
                attached_policies=[],
                group_memberships=[],
                trust_policy=role['AssumeRolePolicyDocument'],
                num_access_keys=0,
                active_password=False,
                is_admin=False
            ))

    # Handle access keys
    output.write("Obtaining Access Keys data for IAM users\n")
    for node in result:
        if arns.get_resource(node.arn).startswith('user/'):
            # Grab access-key count and update node
            user_name = arns.get_resource(node.arn)[5:]
            access_keys_data = iamclient.list_access_keys(UserName=user_name)
            node.access_keys = len(access_keys_data['AccessKeyMetadata'])
            dprint(debug, 'Access Key Count for {}: {}'.format(user_name, len(access_keys_data['AccessKeyMetadata'])))

    return result


def get_unfilled_groups(iamclient, nodes: List[Node], output: io.StringIO = os.devnull, debug=False) -> List[Group]:
    """Using an IAM.Client object, returns a list of Group objects. Adds to each passed Node's group_memberships
    property.

    Does not set Policy objects. Those have to be filled in later.

    Writes high-level progress information to parameter output
    """
    result = []

    # paginate through groups and build result
    output.write("Obtaining IAM groups in the account.\n")
    group_paginator = iamclient.get_paginator('list_groups')
    for page in group_paginator.paginate(PaginationConfig={'PageSize': 25}):
        dprint(debug, 'list_groups page: {}'.format(page))
        for group in page['Groups']:
            result.append(Group(
                arn=group['Arn'],
                attached_policies=[]
            ))

    # loop through group memberships
    output.write("Connecting IAM users to their groups.\n")
    for node in nodes:
        if not arns.get_resource(node.arn).startswith('user/'):
            continue  # skip when not an IAM user
        dprint(debug, 'finding groups for user {}'.format(node.arn))
        user_name = arns.get_resource(node.arn)[5:]
        group_list = iamclient.list_groups_for_user(UserName=user_name)
        for group in group_list['Groups']:
            for group_obj in result:
                if group['Arn'] == group_obj.arn:
                    node.group_memberships.append(group_obj)

    return result


def get_policies_and_fill_out(iamclient, nodes: List[Node], groups: List[Group],
                              output: io.StringIO = os.devnull, debug=False) -> List[Policy]:
    """Using an IAM.Client object, return a list of Policy objects. Adds references to each passed Node and
    Group object where applicable.

    Writes high-level progress information to parameter output
    """
    result = []

    # navigate through nodes and add policy objects if they do not already exist in result
    output.write("Obtaining policies used by all IAM users and roles\n")
    for node in nodes:
        node_name_components = arns.get_resource(node.arn).split('/')
        node_type, node_name = node_name_components[0], node_name_components[-1]
        dprint(debug, 'Grabbing inline policies for {}'.format(node.arn))
        # get inline policies
        if node_type == 'user':
            inline_policy_arns = iamclient.list_user_policies(UserName=node_name)
            # get each inline policy, append it to node's policies and result list
            for policy_name in inline_policy_arns['PolicyNames']:
                dprint(debug, '   Grabbing inline policy: {}'.format(policy_name))
                inline_policy = iamclient.get_user_policy(UserName=node_name, PolicyName=policy_name)
                policy_object = Policy(arn=node.arn, name=policy_name, policy_doc=inline_policy['PolicyDocument'])
                node.attached_policies.append(policy_object)
                result.append(policy_object)
        elif node_type == 'role':
            inline_policy_arns = iamclient.list_role_policies(RoleName=node_name)
            # get each inline policy, append it to the node's policies and result list
            # in hindsight, it's possible this could be folded with the above code, assuming the API doesn't change
            for policy_name in inline_policy_arns['PolicyNames']:
                dprint(debug, '   Grabbing inline policy: {}'.format(policy_name))
                inline_policy = iamclient.get_role_policy(RoleName=node_name, PolicyName=policy_name)
                policy_object = Policy(arn=node.arn, name=policy_name, policy_doc=inline_policy['PolicyDocument'])
                node.attached_policies.append(policy_object)
                result.append(policy_object)

        # get attached policies for users and roles
        if node_type == 'user':
            attached_policies = iamclient.list_attached_user_policies(UserName=node_name)
        else:  # node_type == 'role':
            attached_policies = iamclient.list_attached_role_policies(RoleName=node_name)
        for attached_policy in attached_policies['AttachedPolicies']:
            policy_arn = attached_policy['PolicyArn']
            dprint(debug, '   Grabbing managed policy: {}'.format(policy_arn))
            # reduce API calls, search existing policies for matching arns
            policy_object = _get_policy_by_arn(policy_arn, result)
            if policy_object is None:
                # Gotta retrieve the policy's current default version
                dprint(debug, '      Policy cache miss, calling API')
                policy_response = iamclient.get_policy(PolicyArn=policy_arn)
                dprint(debug, '      Policy version: {}'.format(policy_response['Policy']['DefaultVersionId']))
                policy_version_response = iamclient.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_response['Policy']['DefaultVersionId']
                )
                policy_object = Policy(
                    arn=policy_arn,
                    name=policy_response['Policy']['PolicyName'],
                    policy_doc=policy_version_response['PolicyVersion']['Document']
                )
                result.append(policy_object)
            node.attached_policies.append(policy_object)

    output.write("Obtaining policies used by IAM groups\n")
    for group in groups:
        group_name = arns.get_resource(group.arn).split('/', 1)[-1]  # split by slashes and take the final item
        dprint(debug, 'Getting policies for: {}'.format(group.arn))
        # get inline policies
        inline_policies = iamclient.list_group_policies(GroupName=group_name)
        for policy_name in inline_policies['PolicyNames']:
            dprint(debug, '   Grabbing inline policy: {}'.format(policy_name))
            inline_policy = iamclient.get_group_policy(GroupName=group_name, PolicyName=policy_name)
            policy_object = Policy(arn=group.arn, name=policy_name, policy_doc=inline_policy['PolicyDocument'])
            group.attached_policies.append(policy_object)
            result.append(policy_object)

        # get attached policies
        attached_policies = iamclient.list_attached_group_policies(GroupName=group_name)
        for attached_policy in attached_policies['AttachedPolicies']:
            policy_arn = attached_policy['PolicyArn']
            dprint(debug, '   Grabbing managed policy: {}'.format(policy_arn))
            # check cached policies first
            policy_object = _get_policy_by_arn(policy_arn, result)
            if policy_object is None:
                dprint(debug, '      Policy cache miss, calling API')
                policy_response = iamclient.get_policy(PolicyArn=policy_arn)
                dprint(debug, '      Policy version: {}'.format(policy_response['Policy']['DefaultVersionId']))
                policy_version_response = iamclient.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_response['Policy']['DefaultVersionId']
                )
                policy_object = Policy(
                    arn=policy_arn,
                    name=policy_response['Policy']['PolicyName'],
                    policy_doc=policy_version_response['PolicyVersion']['Document']
                )
                result.append(policy_object)
            group.attached_policies.append(policy_object)

    return result


def _get_policy_by_arn(arn: str, policies: List[Policy]) -> Optional[Policy]:
    """Helper function: pull a Policy object with the same ARN from a list or return None"""
    for policy in policies:
        if arn == policy.arn:
            return policy
    return None
