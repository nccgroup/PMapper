# checkrunner.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

from .ec2checks import EC2Checker
from .iamchecks import IAMChecker
from .lambdachecks import LambdaChecker
from .cloudformationchecks import CloudFormationChecker
from principalmap.awsedge import AWSEdge
import principalmap.queries

import threading

# Object that launches and manages all the different groups of checks
class CheckRunner:
	def __init__(self, session, graph):
		self.session = session
		self.graph = graph

	# This is *THE* method when we pull a graph, which launches our different 
	# threads to find our edges. We're using threading  because we're making a 
	# bunch of API calls over the Internet.
	def runChecks(self):
		targets = []

		# Huge optimization: figure out the admin users and set "admin" edges
		iamclient = self.session.create_client('iam')
		for node in self.graph.nodes:
			node.set_admin(principalmap.queries.privesc.PrivEscQuery.check_self(iamclient, node))
		for x in self.graph.nodes:
			for y in self.graph.nodes:
				if x == y:
					continue
				if x.properties['is_admin']:
					self.graph.edges.append(
						AWSEdge(x, y, 'ADMIN')
					)

		# Compose target tuple list, ignore self and admins 
		for nodeX in self.graph.nodes:
			for nodeY in self.graph.nodes:
				if nodeX == nodeY:
					continue # ignore self-connections
				if nodeX.get_admin():
					continue # ignore admin users
				targets.append((nodeX, nodeY))

		# Create each object to run checks
		checks = [
			EC2Checker(targets, self.session, self.graph), 
			IAMChecker(targets, self.session, self.graph), 
			LambdaChecker(targets, self.session, self.graph),
			CloudFormationChecker(self.graph.nodes, self.session, self.graph)
		]
		
		# Run the checks
		# TODO: threadpool this in the future
		for check in checks:
			check.start()
		for check in checks:
			check.join()

