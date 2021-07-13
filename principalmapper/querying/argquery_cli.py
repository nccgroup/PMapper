"""Code to implement the CLI interface to the argquery component of Principal Mapper"""

#  Copyright (c) NCC Group and Erik Steringer 2020. This file is part of Principal Mapper.
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

import os
from argparse import ArgumentParser, Namespace
import json
import logging

from principalmapper.common import OrganizationTree, Policy
from principalmapper.graphing import graph_actions
from principalmapper.querying import query_utils, query_actions, query_orgs
from principalmapper.util import botocore_tools, arns
from principalmapper.util.storage import get_storage_root

logger = logging.getLogger(__name__)


def provide_arguments(parser: ArgumentParser):
    """Given a parser object (which should be a subparser), add arguments to provide a CLI interface to the
    argquery component of Principal Mapper.
    """
    parser.add_argument(
        '-s',
        '--skip-admin',
        action='store_true',
        help='Ignores administrative principals when querying about multiple principals in an account'
    )
    parser.add_argument(
        '-u',
        '--include-unauthorized',
        action='store_true',
        help='Includes output to say if a given principal is not able to call an action.'
    )
    parser.add_argument(
        '--principal',
        default='*',
        help='A string matching one or more IAM users or roles in the account, or use * (the default) to include all'
    )
    parser.add_argument(
        '--action',
        help='An AWS action to test for, allows * wildcards'
    )
    parser.add_argument(
        '--resource',
        default='*',
        help='An AWS resource (denoted by ARN) to test for'
    )
    parser.add_argument(
        '--condition',
        action='append',
        help='A set of key-value pairs to test specific conditions'
    )
    parser.add_argument(
        '--preset',
        help='A preset query to run'
    )
    argquery_rpolicy_args = parser.add_mutually_exclusive_group()
    argquery_rpolicy_args.add_argument(
        '--with-resource-policy',
        action='store_true',
        help='Retrieves and includes the resource policy for the resource given by the --resource parameter. '
             'Handles S3, IAM, SNS, SQS, and KMS.'
    )
    argquery_rpolicy_args.add_argument(
        '--resource-policy-text',
        help='The full text of a resource policy to consider during authorization evaluation.'
    )
    parser.add_argument(
        '--resource-owner',
        help='The account ID of the owner of the resource. Required for S3 objects (which do not have it in the ARN).'
    )
    parser.add_argument(
        '--session-policy',
        help='The full text of a session policy to consider during authorization evaluation.'
    )
    parser.add_argument(
        '--scps',
        action='store_true',
        help='When specified, the SCPs that apply to the account are taken into consideration.'
    )


def process_arguments(parsed_args: Namespace):
    """Given a namespace object generated from parsing args, perform the appropriate tasks. Returns an int
    matching expectations set by /usr/include/sysexits.h for command-line utilities."""

    if parsed_args.account is None:
        session = botocore_tools.get_session(parsed_args.profile)
    else:
        session = None
    graph = graph_actions.get_existing_graph(session, parsed_args.account)
    logger.debug('Querying against graph {}'.format(graph.metadata['account_id']))

    # process condition args to generate input dict
    conditions = {}
    if parsed_args.condition is not None:
        for arg in parsed_args.condition:
            # split on equals-sign (=), assume first instance separates the key and value
            components = arg.split('=')
            if len(components) < 2:
                print('Format for condition args not matched: <key>=<value>')
                return 64
            key = components[0]
            value = '='.join(components[1:])
            conditions.update({key: value})

    if parsed_args.with_resource_policy:
        resource_policy = query_utils.pull_cached_resource_policy_by_arn(
            graph,
            parsed_args.resource
        )
    elif parsed_args.resource_policy_text:
        resource_policy = json.loads(parsed_args.resource_policy_text)
    else:
        resource_policy = None

    resource_owner = parsed_args.resource_owner
    if resource_policy is not None:
        if parsed_args.resource_owner is None:
            if arns.get_service(resource_policy.arn) == 's3':
                raise ValueError('Must supply resource owner (--resource-owner) when including S3 bucket policies '
                                 'in a query')
            else:
                resource_owner = arns.get_account_id(resource_policy.arn)
        if isinstance(resource_policy, Policy):
            resource_policy = resource_policy.policy_doc

    if parsed_args.scps:
        if 'org-id' in graph.metadata and 'org-path' in graph.metadata:
            org_tree_path = os.path.join(get_storage_root(), graph.metadata['org-id'])
            org_tree = OrganizationTree.create_from_dir(org_tree_path)
            scps = query_orgs.produce_scp_list(graph, org_tree)
        else:
            raise ValueError('Graph for account {} does not have an associated OrganizationTree mapped (need to run '
                             '`pmapper orgs create/update` to get that.')
    else:
        scps = None

    query_actions.argquery(graph, parsed_args.principal, parsed_args.action, parsed_args.resource, conditions,
                           parsed_args.preset, parsed_args.skip_admin, resource_policy,
                           resource_owner, parsed_args.include_unauthorized, parsed_args.session_policy,
                           scps)

    return 0
