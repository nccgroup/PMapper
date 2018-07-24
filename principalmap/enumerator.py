"""
A class to make the needed requests to the AWS API for composing a graph, also
holds class methods to query the simulator.

"""
from __future__ import absolute_import, print_function, unicode_literals

import botocore.session

from .awsedge import *
from .awsgraph import *
from .awsnode import *
from .edgeconditions.checkrunner import CheckRunner


class Enumerator:
	def __init__(self, session):
		self.graph = AWSGraph()
		self.session = session

	def fillOutGraph(self):
		client = self.session.create_client('iam')
		roles = client.list_roles()['Roles']
		users = client.list_users()['Users']
		for user in users:
			self.graph.nodes.append(AWSNode(user['Arn']))
		for role in roles:
			self.graph.nodes.append(AWSNode(role['Arn']))
		
		checkrunner = CheckRunner(self.session, self.graph)
		checkrunner.runChecks()
