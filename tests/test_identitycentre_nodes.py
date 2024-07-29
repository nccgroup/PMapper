import os
import json
import boto3
import sys
sys.path.append('..')
sys.path.append('../..')
from common import Node, Group, Edge
from graph_actions import get_existing_graph
import logging

logger = logging.getLogger(__name__)
# logging.basicConfig(level=logging.INFO, format='%(asctime)s: %(levelname)s: %(message)s')
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Variables
aws_organisations_account = ""

def get_sso_credentials(credential_name):
    dir = os.path.expanduser('~/.aws/sso/cache')

    json_files = [pos_json for pos_json in os.listdir(dir) if pos_json.endswith('.json')]

    for json_file in json_files:
        path = os.path.join(dir, json_file)
        with open(path) as file:
            data = json.load(file)
            if 'accessToken' in data:
                accessToken = data['accessToken']

    client = boto3.client('sso', region_name='eu-west-1')
    response = client.get_role_credentials(
        roleName='Ozow_Security_Audit',
        accountId=str(credential_name),
        accessToken=accessToken
    )

    return response

def get_identitycenter_groups(sso_session, sso_instance):
    print("\nSSO Identitystore Groups:")
    identitystore_client = sso_session.client('identitystore')
    groups_paginate = identitystore_client.get_paginator('list_groups')
    obj_groups = []

    for groups in groups_paginate.paginate(IdentityStoreId=sso_instance["IdentityStoreId"]):
        groups = groups["Groups"]

        for group in groups:
            G = Group(
                    arn="arn:aws:identitystore:::group/" + group["GroupId"],
                    attached_policies=[]
                )
            obj_groups.append(G)
            print("\t{:<40} {}".format(group["DisplayName"], G.arn))

    return obj_groups

def get_identitycenter_users(sso_session, sso_instance):
    
    def generate_group_membership_edge(user_arn, group_arn):
        return Edge(
            source=user_arn, # User arn
            destination=group_arn, # Group arn
            reason="Identity Centre group membership",
            short_reason="group_membership"
        )

    print("\nSSO Identitystore Users:")
    identitystore_client = sso_session.client('identitystore')
    users_paginate = identitystore_client.get_paginator('list_users')
    group_memberships_client = identitystore_client.get_paginator('list_group_memberships_for_member')
    obj_nodes = []
    obj_edges = []

    for users in users_paginate.paginate(IdentityStoreId=sso_instance["IdentityStoreId"]):
        users = users["Users"]

        for user in users:
            user_arn = "arn:aws:identitystore:::user/" + user["UserId"]
            group_membership_arns = []

            for group_memberships in group_memberships_client.paginate(IdentityStoreId=sso_instance["IdentityStoreId"], MemberId={"UserId": user["UserId"]}):
                group_memberships = group_memberships["GroupMemberships"]
                group_membership_arns = [Group(arn="arn:aws:identitystore:::group/" + group_membership["GroupId"], attached_policies=[])  for group_membership in group_memberships]
                
                for group_membership_arn in group_membership_arns:
                    obj_edges.append(generate_group_membership_edge(user_arn, group_membership_arn.arn))

            N = Node(
                user_arn,
                user["UserId"],
                [], 
                group_membership_arns,
                None,
                None,
                0,
                False,
                False,
                None, 
                False,
                {}
            )
            obj_nodes.append(N)
            print("\t{:<40} {}".format(user["UserName"], N.arn))

    return obj_nodes, obj_edges

def get_identitycenter_permission_sets(sso_session, sso_instance):
    
    def generate_account_assignment_edge(graph_objs, account_id, permission_set_name, source_principal_arn):

        def get_permission_set_role(graph, permission_set_name) -> Node:
            permission_set_name_prefix = f"AWSReservedSSO_{permission_set_name}_"
            return next(
                node for node in graph.nodes
                if permission_set_name_prefix in node.arn
            )

        graph = next(graph for graph in graph_objs if graph.metadata['account_id'] == account_id)
        role = get_permission_set_role(graph,permission_set_name)
        return Edge(
            source=source_principal_arn, # User or group arn
            destination=role.arn,
            reason="Identity Centre provisioned access",
            short_reason="identitystore"
        )
    
    print("\nSSO Identitystore Permission Sets:")
    organization_accounts = sso_session.client('organizations').list_accounts()['Accounts']
    sso_admin_client = sso_session.client('sso-admin')
    permission_sets_paginate = sso_admin_client.get_paginator('list_permission_sets_provisioned_to_account')
    account_assignments_paginate = sso_admin_client.get_paginator('list_account_assignments')
    obj_edges = []
    graph_objs = []

    for account in organization_accounts:
        account_id = account['Id']
        try:
            g = get_existing_graph(session = None, account=account_id)
            logger.debug("%s", g)
            graph_objs.append(g)
        except:
            logger.warning('\n[!] Unable to load a Graph object for account {}, possibly because it is not mapped yet. '
                            'Please map all accounts and then update the Organization Tree '
                            '(`pmapper orgs update --org $ORG_ID`).\n'.format(account_id))
            continue

        for permission_sets in permission_sets_paginate.paginate(InstanceArn=sso_instance["InstanceArn"], AccountId=account_id):
            permission_sets = permission_sets.get('PermissionSets', [])
            
            for permission_set in permission_sets:
                
                for account_assignments in account_assignments_paginate.paginate(InstanceArn=sso_instance["InstanceArn"], AccountId=account_id, PermissionSetArn=permission_set):
                    account_assignments = account_assignments["AccountAssignments"]
                    
                    for account_assignment in account_assignments:
                        permission_set_information = sso_admin_client.describe_permission_set(InstanceArn=sso_instance["InstanceArn"], PermissionSetArn=account_assignment['PermissionSetArn'])
                        permission_set_name = permission_set_information["PermissionSet"]["Name"]
                        principal_type = account_assignment['PrincipalType'].lower()
                        principal_id = account_assignment['PrincipalId']
                        source_principal_arn = "arn:aws:identitystore:::{}/{}".format(principal_type, principal_id)
                        logger.debug("%s %s %s", account_id, permission_set_name, source_principal_arn)

                        E = generate_account_assignment_edge(graph_objs, account_id, permission_set_name, source_principal_arn)
                        obj_edges.append(E)
                        print("\t{} -> {}".format(E.source, E.destination))
    
    return obj_edges

if __name__ == "__main__":

    sso_credentials = get_sso_credentials(aws_organisations_account)
    session = boto3.Session(
        aws_access_key_id=sso_credentials['roleCredentials']['accessKeyId'],
        aws_secret_access_key=sso_credentials['roleCredentials']['secretAccessKey'],
        aws_session_token=sso_credentials['roleCredentials']['sessionToken'],
        region_name='eu-west-1'
    )
    sso_admin_client = session.client('sso-admin')
    sso_instances = sso_admin_client.list_instances()["Instances"]
    print(json.dumps(sso_instances, indent=2))

    for sso_instance in sso_instances:

        obj_groups = get_identitycenter_groups(session, sso_instance)
        obj_nodes, obj_edges = get_identitycenter_users(session, sso_instance)
        obj_edges = obj_edges + (get_identitycenter_permission_sets(session, sso_instance))
        

        