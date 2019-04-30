#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import botocore.session
import logging
import os
import os.path
import sys

import principalmap.enumerator
from principalmap.querying import perform_query
from principalmap.visualizing import perform_visualization
from principalmap.awsgraph import AWSGraph
from principalmap.awsnode import AWSNode
from principalmap.awsedge import AWSEdge


def main():
    mainparser = argparse.ArgumentParser()
    mainparser.add_argument('--profile', help='Profile stored for the AWS CLI')
    mainparser.add_argument('--env-vars', action='store_true', help='Use environment variables for credentials.')
    subparsers = mainparser.add_subparsers(
        title='subcommands',
        description='The different functionalities of this tool.',
        dest='picked_cmd',
        help='Select one to execute.'
    )
    graphparser = subparsers.add_parser(
        'graph',
        help='For pulling information from an AWS account.',
        description='Uses the botocore library to query the AWS API and compose a graph of principal relationships. By default, running this command will create a graph.'
    )
    graphparser.add_argument('--display', action='store_true', help='Displays stored graph rather than composing one.')
    queryparser = subparsers.add_parser(
        'query',
        help='For querying the graph pulled from an AWS account.',
        description='Uses a created graph to provide a query interface, executes the passed query. It also will make calls to the AWS API.'
    )
    queryparser.add_argument('query_string', help='The query to run against the endpoint.')
    queryparser.add_argument('-s', '--skip-admin', action='store_true', help='Skip admin principals when running a query.')
    visualparser = subparsers.add_parser(
        'visualize',
        help='For visualizing the pulled graph.',
        description='Creates a visualization of the passed graph.'
    )

    parsed = mainparser.parse_args(sys.argv[1:])
    if parsed.profile is not None and parsed.env_vars:
        print('Cannot use both a profile and environment variables.')
        sys.exit(-1)

    session = create_session(parsed)
    if session is None:
        print('Could not obtain caller identity.')
        if parsed.profile is not None:
            print('Validate the credentials for profile ' + parsed.profile + '.')
        sys.exit(-1)

    if parsed.picked_cmd == 'graph':
        handle_graph(parsed, session)
    elif parsed.picked_cmd == 'query':
        handle_query(parsed, session)
    elif parsed.picked_cmd == 'visualize':
        handle_visualize(parsed, session)


def create_session(parsed):
    """A function to create a botocore session.

    Returns None if there aren't any valid creds available."""
    result = None
    if parsed.env_vars:
        access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
        secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        session_token = os.environ.get('AWS_SESSION_TOKEN')
        result = botocore.session.Session()
        if access_key_id is not None and secret_key is not None:
            result.set_credentials(access_key_id, secret_key, session_token)
        else:
            return None
    else:
        if parsed.profile is None:
            result = botocore.session.Session(profile='default')
            parsed.profile = 'default'
        else:
            result = botocore.session.Session(profile=parsed.profile)
        result.get_credentials() #  trip exception if profile doesn't exist

    # Attempt to use the session to validate that it can be used
    try:
        result.create_client('sts').get_caller_identity()
    except:
        return None

    return result


def get_graph_file(parsed, account, mode):
    """Retrieve file object, handling if it's a principal in the credentials file or environment variables."""
    dirpath = ''
    filepath = ''
    if parsed.env_vars:
        dirpath = os.path.join(os.path.expanduser('~'), '.principalmap-acct/')
        filepath = os.path.join(dirpath, 'graphfile-' + account)
    else:
        dirpath = os.path.join(os.path.expanduser('~'), '.principalmap/')
        filepath = os.path.join(dirpath, 'graphfile-' + parsed.profile)

    if not os.path.exists(dirpath):
        os.makedirs(dirpath)
    return open(filepath, mode)


def handle_graph(parsed, session):
    identity_response = session.create_client('sts').get_caller_identity()
    account = identity_response['Account']
    caller  = identity_response['Arn']

    if not parsed.display:
        if parsed.profile is not None:
            print('Using profile: ' + parsed.profile)
        print('Pulling data for account ' + identity_response['Account'])
        print('Using principal with ARN ' + identity_response['Arn'])
        graph = pull_graph(parsed, session)
        print('Created an ' + str(graph))
        graphfile = get_graph_file(parsed, account, "w+")
        graphfile.write("# Graph file generated by Principal Mapper\n")
        graph.write_to_fd(graphfile)
    else:
        graphfile = get_graph_file(parsed, account, "r")
        graph = graph_from_file(graphfile)
        print(str(graph))


def handle_query(parsed, session):
    identity_response = session.create_client('sts').get_caller_identity()
    account = identity_response['Account']
    graphfile = get_graph_file(parsed, account, "r")
    graph = graph_from_file(graphfile)

    perform_query(parsed.query_string, session, graph, parsed.skip_admin)


def handle_visualize(parsed, session):
    identity_response = session.create_client('sts').get_caller_identity()
    account = identity_response['Account']
    graphfile = get_graph_file(parsed, account, "r")
    graph = graph_from_file(graphfile)

    perform_visualization(parsed, account, session, graph)


def pull_graph(parsed, session):
    enumerator = principalmap.enumerator.Enumerator(session)
    enumerator.fillOutGraph()

    return enumerator.graph


def graph_from_file(graphfile):
    result = AWSGraph()
    mode = 'headers'
    for line in graphfile:
        if line == "\n":
            break
        if mode == 'headers':
            if line[0] != '#':
                mode = 'nodes'
            else:
                pass  # ignoring headers
        if mode == 'nodes':
            if "[NODES]" in line:
                pass
            elif "[EDGES]" in line:
                mode = 'edges'
            else:
                node = eval(line)
                result.nodes.append(eval(line))
        if mode == 'edges':
            if "[EDGES]" in line:
                pass
            else:
                pair = eval(line)
                result.edges.append(AWSEdge(result.nodes[pair[0]], result.nodes[pair[1]], pair[2], pair[3]))
    return result


if __name__ == '__main__':
    main()
