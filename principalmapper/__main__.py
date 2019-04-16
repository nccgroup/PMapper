"""
Provides a command-line interface to use the principalmapper library
"""

import argparse
import logging


def main():
    """Point of entry for command-line"""
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument(
        '--profile',
        help='AWS CLI (botocore) profile to use to call the AWS API'
    )
    argument_parser.add_argument(
        '--debug',
        action='store_true',
        help='Produces debug-level output'
    )
    argument_parser.add_argument(
        '--account',
        help='When running offline operations, this '
    )

    # Create subparser for various subcommands
    subparser = argument_parser.add_subparsers(
        title='subcommand',
        description='The subcommand to use among this suite of tools',
        dest='picked_cmd',
        help='Select a subcommand to execute'
    )

    # Graph subcommand
    graphparser = subparser.add_parser(
        'graph',
        description='Obtains information about a specific AWS account\'s use of IAM for analysis.',
        help='Pulls information for an AWS account\'s use of IAM.'
    )
    command_group = graphparser.add_mutually_exclusive_group(required=True)
    command_group.add_argument(
        '--create',
        action='store_true',
        help='Creates a completely new graph for an AWS account, wiping away any old data.'
    )
    command_group.add_argument(
        '--display',
        action='store_true',
        help='Displays information about a currently-stored graph based on the AWS credentials used.'
    )
    command_group.add_argument(
        '--update-nodes',
        action='store_true',
        help='Updates which principals are available in an AWS account. Deletes IAM users or roles that are no longer '
             'present. Removes edges for deleted IAM users or roles. Does not add new edges.'
    )
    command_group.add_argument(
        '--update-edges',
        action='store_true',
        help='Updates the edges of an AWS account. Does not gather information about IAM users or roles.'
    )

    # Query subcommand
    queryparser = subparser.add_parser(
        'query',
        description='Displays information corresponding to a roughly human-readable query.',
        help='Displays information corresponding to a query'
    )
    queryparser.add_argument(
        '-s',
        '--skip-admin',
        action='store_true',
        help='Ignores "admin" level principals when querying about multiple principals in an account'
    )
    queryparser.add_argument(
        'query',
        help='The query to execute.'
    )

    # New Query subcommand
    argqueryparser = subparser.add_parser(
        'argquery',
        description='Displays information corresponding to a arg-specified query.',
        help='Displays information corresponding to a query'
    )
    argqueryparser.add_argument(
        '-s',
        '--skip-admin',
        action='store_true',
        help='Ignores "admin" level principals when querying about multiple principals in an account'
    )
    argqueryparser.add_argument(
        '--principal',
        default='*',
        help='A string matching one or more IAM users or roles in the account, allows * wildcards'
    )
    argqueryparser.add_argument(
        '--action',
        default='*',
        help='An AWS action to test for, allows * wildcards'
    )
    argqueryparser.add_argument(
        '--resource',
        default='*',
        help='An AWS resource (denoted by ARN) to test for.'
    )
    # TODO: --condition arg
    # argqueryparser.add_argument(
    #     '--condition',
    #     help='A set of key-value pairs to test specific conditions'
    # )

    # REPL subcommand
    replparser = subparser.add_parser(
        'repl',
        description='Runs a read-evaluate-print-loop of queries, avoiding the need to read from disk for each query',
        help='Runs a REPL for querying'
    )

    # Visualization subcommand
    visualizationparser = subparser.add_parser(
        'visualize',
        description='Generates an image file to display information about an AWS account',
        help='Generates an image representing the AWS account'
    )
    visualizationparser.add_argument(
        '--filetype',
        default='svg',
        choices=['svg', 'png'],
        help='The (lowercase) filetype to output the image as.'
    )

    # TODO: Cross-Account subcommand

    # TODO: Recommendations subcommand

    parsed_args = argument_parser.parse_args()

    logger = setup_logger(parsed_args)

    logger.debug('Parsed Arguments: ' + str(parsed_args))
    if parsed_args.picked_cmd == 'graph':
        handle_graph(parsed_args)
    elif parsed_args.picked_cmd == 'query':
        handle_query(parsed_args)
    elif parsed_args.picked_cmd == 'argquery':
        handle_argquery(parsed_args)
    elif parsed_args.picked_cmd == 'repl':
        handle_repl(parsed_args)
    elif parsed_args.picked_cmd == 'visualize':
        handle_visualization(parsed_args)
    return 0


def setup_logger(parsed_args):
    """Configures the logger module."""
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if parsed_args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    logger.debug('Debug status: ' + str(parsed_args.debug))
    return logger


def handle_graph(parsed_args):
    """Processes the arguments for the graph subcommand and executes related tasks"""
    pass


def handle_query(parsed_args):
    """Processes the arguments for the query subcommand and executes related tasks"""
    pass


def handle_argquery(parsed_args):
    """Processes the arguments for the argquery subcommand and executes related tasks"""
    pass


def handle_repl(parsed_args):
    """Processes the arguments for the query REPL and initiates"""
    pass


def handle_visualization(parsed_args):
    """Processes the arguments for the visualization subcommand and executes related tasks"""
    pass
