import logging

from neo4j import GraphDatabase
from principalmapper.common import Graph, Node, Group
from principalmapper.util import arns

logger = logging.getLogger(__name__)

uri = "neo4j://localhost:7687"

def load_nodes_to_neo4j(nodes, account_id, session):
    for node in nodes:
        # Add the node to neo4j
        # Check if node is an object and convert to dictionary
        if not type(node) == Node:
            node_dict = node
            node = Node(**node)
        else:
            node_dict = node.to_dictionary()  # Convert Node object to a dictionary
        labels = []
        node_type = 'User' if 'user/' in node.arn else 'Role'  # Differentiate between User and Role
        labels.append(node_type)
        labels.append('Principal')
        if node.is_admin:
            labels.append('Admin')
        label = ':'.join(labels)
        node_name = '/'.join(node.searchable_name().split('/')[1:])
        if node_dict.get("username"):
            node_name = node_dict.get("username")
        session.run(f"""
            MERGE (n:{label} {{
                arn: $arn, 
                id_value: $id_value, 
                active_password: $active_password, 
                access_keys: $access_keys, 
                is_admin: $is_admin, 
                has_mfa: $has_mfa,
                account_id: $account_id,
                name: $node_name
            }})
        """, **node_dict, account_id=account_id, node_name=node_name)
        # Handle tags separately
        # if node.tags:
        #     add_tags_to_neo4j(node.arn, node.tags, session)
    logger.info(f"Loaded users and roles into Neo4j")

def add_tags_to_neo4j(node_arn, tags, session):
    for key, value in tags.items():
        session.run("""
            MATCH (n {arn: $arn})
            MERGE (t:Tag {key: $key, value: $value})
            MERGE (n)-[:HAS_TAG]->(t)
        """, arn=node_arn, key=key, value=value)

def load_policies_to_neo4j(policies, account_id, session):
    for policy in policies:
        labels = []
        node_type = 'Policy'
        labels.append(node_type)
        # labels.append(account_id)
        label = ':'.join(labels)
        session.run(f"""
            MERGE (p:{label} {{arn: $arn, name: $name, account_id: $account_id}})
        """, arn=policy.arn, name=policy.name, account_id=account_id)
    logger.info(f"Loaded policies into Neo4j")

def load_groups_to_neo4j(groups, account_id, session):
    for group in groups:
        # Check if group is an object and convert to dictionary
        try:
            group_dict = group.to_dictionary()  # Convert Node object to a dictionary
        except:
            group_dict = group
        labels = []
        node_type = 'Group'
        labels.append(node_type)
        # labels.append(account_id)
        label = ':'.join(labels)
        # Identity Center groups use display_name
        name = group_dict["display_name"] if group_dict["display_name"] else arns.get_resource_name(group_dict["arn"])
        session.run(f"""
            MERGE (g:{label} {{arn: $arn, account_id: $account_id, name: $name}})
        """, **group_dict, account_id=account_id, name=name)
    logger.info(f"Loaded groups into Neo4j")

def create_relationships(nodes, session):
    for node in nodes:

        if not type(node) == Node:
            node = Node(**node)

        for policy in node.attached_policies:
            session.run("""
                MATCH (n), (p:Policy)
                WHERE n.arn = $node_arn AND p.arn = $policy_arn
                MERGE (n)-[:ATTACHED_POLICY]->(p)
            """, node_arn=node.arn, policy_arn=policy.arn)

        for group in node.group_memberships:

            if not type(group) == Group:
                group = Group(arn=group, attached_policies=[])

            session.run("""
                MATCH (n), (g:Group)
                WHERE n.arn = $node_arn AND g.arn = $group_arn
                MERGE (n)-[:MEMBER_OF]->(g)
            """, node_arn=node.arn, group_arn=group.arn)
    logger.info(f"Created node relationships to policies and groups")

def load_edges_to_neo4j(edges, session):
    # edges = filter_edges(edges)
    for edge in edges:
        # Assuming edge has source and destination attributes
        session.run("""
            MATCH (a), (b)
            WHERE a.arn = $source_arn AND b.arn = $destination_arn AND a.is_admin = false
            MERGE (a)-[:EDGE {type: $type, reason: $reason}]->(b)
        """, source_arn=edge.source.arn, destination_arn=edge.destination.arn, type=edge.short_reason, reason=edge.reason)
    logger.info(f"Loaded edges into Neo4j")

def load_cross_account_edges_to_neo4j(edges):
    driver = GraphDatabase.driver(uri, auth=("neo4j", ""))
    with driver.session() as session:
        for edge in edges:
            # Assuming edge has source and destination attributes
            session.run("""
                MATCH (a), (b)
                WHERE a.arn = $source_arn AND b.arn = $destination_arn
                MERGE (a)-[:CROSS_ACCOUNT_ACCESS {type: $type, reason: $reason}]->(b)
            """, source_arn=edge['source'], destination_arn=edge['destination'], type=edge['short_reason'], reason=edge['reason'])
        logger.info(f"Loaded cross account edges into Neo4j")

def load_identitycentre_edges_to_neo4j(edges):
    driver = GraphDatabase.driver(uri, auth=("neo4j", ""))
    with driver.session() as session:
        for edge in edges:
            # Assuming edge has source and destination attributes
            session.run("""
                MATCH (a), (b)
                WHERE a.arn = $source_arn AND b.arn = $destination_arn
                MERGE (a)-[:IDENTITYCENTRE_ACCESS {type: $type, reason: $reason}]->(b)
            """, source_arn=edge['source'], destination_arn=edge['destination'], type=edge['short_reason'], reason=edge['reason'])
        logger.info(f"Loaded IdentityCentre edges into Neo4j")

def load_external_edges_to_neo4j(edges, external_accounts):
    driver = GraphDatabase.driver(uri, auth=("neo4j", ""))

    with driver.session() as session:
        # Add external accounts as nodes
        for account_id in external_accounts:
            labels = []
            node_type = 'External_Account'
            labels.append(node_type)
            label = ':'.join(labels)
            arn = f"arn:aws:iam::{account_id}:root"
            is_admin = False
            session.run(f"""
                MERGE (g:{label} {{arn: $arn, account_id: $account_id, is_admin: $is_admin}})
            """, arn=arn, account_id=account_id, is_admin=is_admin)
        logger.info(f"Loaded external accounts into Neo4j")


        for edge in edges:
            # Assuming edge has source and destination attributes
            session.run("""
                MATCH (a), (b)
                WHERE a.arn = $source_arn AND b.arn = $destination_arn
                MERGE (a)-[:EXTERNAL_ACCESS {type: $type, reason: $reason}]->(b)
            """, source_arn=edge.source, destination_arn=edge.destination, type=edge.short_reason, reason=edge.reason)
        logger.info(f"Loaded external account edges into Neo4j")


def filter_edges(edges):
    # Making a function as we might want to expand on this.
    # Should actually do this in cypher, dont want to miss attack paths where this is an inbetween step (although unlikely, that if you can use this to pivot to admin (through IAM actions), then you should be able to do those actions to the admin roles)
    return [
        edge
        for edge in edges
        if not edge.destination.arn.endswith('AWSServiceRoleForSSO')
    ]

def load_graph_to_neo4j(graph: Graph) -> None:
    driver = GraphDatabase.driver(uri, auth=("neo4j", ""))
    with driver.session() as session:
        account_id = graph.metadata['account_id']
        logger.info(f"Loading graph for account {account_id} into Neo4j")
        # Not adding these for now to improve performance
        # TODO: Create different types of edges to make more performant Neo4j queries
        # load_policies_to_neo4j(graph.policies, account_id, session)
        # load_groups_to_neo4j(graph.groups, account_id, session)
        load_nodes_to_neo4j(graph.nodes, account_id, session)
        # create_relationships(graph.nodes, session)
        load_edges_to_neo4j(graph.edges, session)

def load_identitycentre_to_neo4j(org_tree) -> None:
    driver = GraphDatabase.driver(uri, auth=("neo4j", ""))
    with driver.session() as session:
        for identity_store in org_tree.identity_stores:
            load_nodes_to_neo4j(identity_store["users"], org_tree.org_id, session)
            load_groups_to_neo4j(identity_store["group"], org_tree.org_id, session)
            create_relationships(identity_store["users"], session)
            load_identitycentre_edges_to_neo4j(identity_store["group_edges"])


# Deleted 3806 nodes, deleted 15257 relationships
# No relationships from admin nodes:
#   Deleted 3806 nodes, deleted 13848 relationships
# No policies or groups:
#   Deleted 1264 nodes, deleted 3396 relationships