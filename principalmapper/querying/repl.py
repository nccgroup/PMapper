"""Code that implements a Read-Evaluated-Print-Loop (REPL) for the query interfaces of Principal Mapper."""

#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
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

import argparse
import shlex
import sys

from principalmapper.common import Graph
from principalmapper.querying import query_actions


class PMapperREPL:
    """The Principal Mapper REPL class, handles the state and interactions of the REPL."""

    def __init__(self, graph: Graph):
        self.cmd_history = []
        self.graph = graph

        self.argparser = argparse.ArgumentParser()
        self.argparser.add_argument('-d', '--debug', help='Enable debugging for this command.')
        self.subparsers = self.argparser.add_subparsers(
            title='subcommand',
            dest='subcommand',
            description='The command to run: query, argquery, help, exit'
        )
        self.helpparser = self.subparsers.add_parser('help')
        self.exitparser = self.subparsers.add_parser('exit')
        # TODO: Add graphdata subcommand

        self.queryparser = self.subparsers.add_parser(
            'query',
            description='Displays information corresponding to a roughly human-readable query.',
            help='Displays information corresponding to a query'
        )
        self.queryparser.add_argument(
            '-s',
            '--skip-admin',
            action='store_true',
            help='Ignores "admin" level principals when querying about multiple principals in an account'
        )
        self.queryparser.add_argument(
            'query',
            help='The query to execute.'
        )

        # New Query subcommand
        self.argqueryparser = self.subparsers.add_parser(
            'argquery',
            description='Displays information corresponding to a arg-specified query.',
            help='Displays information corresponding to a query'
        )
        self.argqueryparser.add_argument(
            '-s',
            '--skip-admin',
            action='store_true',
            help='Ignores administrative principals when querying about multiple principals in an account'
        )
        self.argqueryparser.add_argument(
            '--principal',
            default='*',
            help='A string matching one or more IAM users or roles in the account, or use * (the default) to include '
                 'all'
        )
        self.argqueryparser.add_argument(
            '--action',
            help='An AWS action to test for, allows * wildcards'
        )
        self.argqueryparser.add_argument(
            '--resource',
            default='*',
            help='An AWS resource (denoted by ARN) to test for'
        )
        self.argqueryparser.add_argument(
            '--condition',
            action='append',
            help='A set of key-value pairs to test specific conditions'
        )
        self.argqueryparser.add_argument(
            '--preset',
            help='A preset query to run'
        )

    def begin_repl(self):
        """The meat of our work: Read, Eval, Print, and Loop"""
        print('##############################')
        print('#                            #')
        print('#   Principal Mapper REPL    #')
        print('#                            #')
        print('##############################')
        print()
        while True:
            # Read
            try:
                # TODO: handle key-up/down for command history (instead of input()?)
                # TODO: handle key-left/right gracefully
                # TODO: handle tabbing gracefully
                command = input('repl> ')
                # TODO: save input to history (cmd_history list)
            except KeyboardInterrupt as ex:
                print('Ctrl+C detected. Exiting.')
                break

            # Eval/Print
            try:
                args = shlex.split(command)
                parsed_args = self.argparser.parse_args(args)
                if parsed_args.subcommand == 'query':
                    query_actions.query_response(self.graph, parsed_args.query, parsed_args.skip_admin, sys.stdout,
                                                 parsed_args.debug)

                elif parsed_args.subcommand == 'argquery':
                    conditions = {}
                    if parsed_args.condition is not None:
                        for arg in parsed_args.condition:
                            # split on equals-sign (=), assume first instance separates the key and value
                            components = arg.split('=')
                            if len(components) < 2:
                                raise ValueError('Format for condition args not matched: <key>=<value>')
                            key = components[0]
                            value = '='.join(components[1:])
                            conditions.update({key: value})

                    query_actions.argquery(self.graph, parsed_args.principal, parsed_args.action, parsed_args.resource,
                                           conditions, parsed_args.preset, parsed_args.skip_admin, sys.stdout,
                                           parsed_args.debug)

                elif parsed_args.subcommand == 'help':
                    self._print_help()
                elif parsed_args.subcommand == 'exit':
                    print('Exiting.')
                    break
                else:
                    self._print_help()
            except KeyboardInterrupt as ex:
                print('Ctrl+C detected. Exiting.')
                break
            except Exception as ex:
                print('Encountered an error when executing input: {}'.format(command))
                print(ex.args)

            # Loop

    @staticmethod
    def _print_help():
        """Prints a helppage for using the REPL."""
        print('''##### How to Use the Principal Mapper REPL #####
        
Available Commands:
   * query
   * argquery
   * help
   * exit
   
The query/argquery commands behave the same as calling it from the regular 
command line. You must include quotation marks or apostrophes around the 
query for query commands, as the input is parsed like you were on the command 
line. 
   
Simple English(-ish) Querying:
   repl> query 'who can do s3:GetObject with arn:aws:s3:::<some bucket>/<sensitive object>'
   repl> query 'can user/PowerUser do iam:CreateUser'
   repl> query 'can user/PowerUser do sts:AssumeRole with * when aws:MultiFactorAuthPresent=true'
   
Using Argquery:
   repl> argquery --principal user/PowerUser --action ec2:RunInstances
   repl> argquery --action s3:GetObject --resource '*'

Skipping Results for Admins (-s or --skip-admin both work):
   repl> query -s 'who can do s3:GetObject with *'
   repl> argquery --skip-admin --principal '*' --action s3:GetObject --resource '*'

Using Preset Queries:
   repl> query 'preset privesc *'
   repl> argquery --principal user/PowerUser --resource role/AssumableRole --preset connected
''')
