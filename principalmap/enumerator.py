"""
A class to make the needed requests to the AWS API for composing a graph, also
holds class methods to query the simulator.

"""
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

from .awsgraph import *
from .awsnode import *
from .awsedge import *

from .edgeconditions.checkrunner import CheckRunner

import botocore.session

class Enumerator:
    def __init__(self, session):
        self.graph = AWSGraph()
        self.session = session

    def fillOutGraph(self):
        iamclient = self.session.create_client('iam')
        roles = self._get_roles(iamclient)
        users = self._get_users(iamclient)
        for user in users:
            self.graph.nodes.append(AWSNode(user['Arn']))
        for role in roles:
            self.graph.nodes.append(AWSNode(role['Arn']))
        
        checkrunner = CheckRunner(self.session, self.graph)
        checkrunner.runChecks()

    def _get_roles(self, iamclient):
        """(Internal) Get roles, handle pagination."""
        result = []
        response = iamclient.list_roles()
        result.extend(response['Roles'])
        while response['IsTruncated']:
            response = iamclient.list_roles(Marker=response['Marker'])
            result.extend(response['Roles'])
        return result

    def _get_users(self, iamclient):
        """(Internal) Get users, handle pagination."""
        result = []
        response = iamclient.list_users()
        result.extend(response['Users'])
        while response['IsTruncated']:
            response = iamclient.list_users(Marker=response['Marker'])
            result.extend(response['Users'])
        return result

