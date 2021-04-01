#  Copyright (c) NCC Group and Erik Steringer 2021. This file is part of Principal Mapper.
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

"""This is an example Python 3 script that creates a Graph object based on the contents of an
AWS CloudFormation Template

The goal of this script is to help enable 'push-left' and get value out of PMapper earlier
in the infrastructure lifecycle.

Future improvements:

* Support all resource types that PMapper supports along with potential edges
* Support other infra-as-code options (Terraform)
"""

import argparse
import json

import yaml

import principalmapper
from principalmapper.common import Graph, Node
from principalmapper.graphing import gathering, graph_actions, iam_edges, sts_edges


def _resolve_string(resources, element) -> str:
    """Given a thing that can be an object or string, turn it into a string. Handles stuff like
    { "Fn::GetAtt": "..." } and turns it into a string."""
    raise NotImplementedError('TODO: implement string handling/resolution')


def _generate_iam_id(node_type: str, counter: int) -> str:
    """Internal method to generate fake IDs for IAM resources. Format is derived from
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
    """

    if node_type == 'user':
        return 'AIDA{0:016d}'.format(counter)
    elif node_type == 'role':
        return 'AROA{0:016d}'.format(counter)
    elif node_type == 'group':
        return 'AGPA{0:016d}'.format(counter)
    elif node_type == 'policy':
        return 'ANPA{0:016d}'.format(counter)
    else:
        raise ValueError('Unexpected value {} for node_type param'.format(node_type))


def main():
    """Body of the script."""

    # handle arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--account', default='000000000000', help='The account ID to assign the simulated Graph')

    file_arg_group = parser.add_mutually_exclusive_group(required=True)
    file_arg_group.add_argument('--json', help='The CloudFormation JSON template file to read from')
    file_arg_group.add_argument('--yaml', help='The CloudFormation YAML template file to read from')
    parsed_args = parser.parse_args()

    # Parse file
    if parsed_args.json:
        print('[+] Loading file {}'.format(parsed_args.json))
        fd = open(parsed_args.json)
        data = json.load(fd)
    else:
        print('[+] Loading file {}'.format(parsed_args.yaml))
        fd = open(parsed_args.yaml)
        data = yaml.safe_load(fd)
    fd.close()

    # Create metadata
    metadata = {
        'account_id': parsed_args.account,
        'pmapper_version': principalmapper.__version__
    }

    print('[+] Building a Graph object for an account with ID {}'.format(metadata['account_id']))

    if 'Resources' not in data:
        print('[!] Missing required template element "Resources"')
        return -1

    # Create space to stash all the data we generate
    groups = []
    policies = []
    nodes = []

    # Handle data from IAM
    iam_id_counter = 0
    template_resources = data['Resources']
    # TODO: Handle policies to start
    # TODO: Handle groups
    for logical_id, contents in template_resources.items():
        # Get data on IAM Users and Roles
        if contents['Type'] == 'AWS::IAM::User':
            properties = contents['Properties']
            node_path = '/' if 'Path' not in properties else properties['Path']
            node_arn = 'arn:aws:iam::{}:user{}'.format(
                metadata['account_id'],
                '{}{}'.format(node_path, properties['UserName'])
            )
            print('[+] Adding user {}'.format(node_arn))
            nodes.append(
                Node(
                    node_arn,
                    _generate_iam_id('user', iam_id_counter),
                    [],  # TODO: add policy handling
                    [],  # TODO: add group handling
                    None,
                    None,
                    0,  # TODO: fix access keys stuff
                    False,  # TODO: fix password handling
                    False,  # TODO: implement admin checks
                    None,  # TODO: handle permission boundaries
                    False,  # TODO: handle MFA stuff in CF template reading
                    {}  # TODO: add tag handling
                )
            )
            iam_id_counter += 1

        elif contents['Type'] == 'AWS::IAM::Role':
            properties = contents['Properties']
            # TODO: finish out roles

    # TODO: update access keys for users

    # Sort out administrative principals
    gathering.update_admin_status(nodes)

    # Create Edges
    edges = iam_edges.generate_edges_locally(nodes) + sts_edges.generate_edges_locally(nodes)

    # Create our graph and finish
    graph = Graph(nodes, edges, policies, groups, metadata)
    graph_actions.print_graph_data(graph)


if __name__ == '__main__':
    main()
