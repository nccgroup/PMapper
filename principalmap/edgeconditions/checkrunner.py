# checkrunner.py

from __future__ import absolute_import, print_function, unicode_literals

from tqdm import tqdm

import principalmap.queries
from principalmap.awsedge import AWSEdge

from .cloudformationchecks import CloudFormationChecker
from .ec2checks import EC2Checker
from .iamchecks import IAMChecker
from .lambdachecks import LambdaChecker


# Object that launches and manages all the different groups of checks
class CheckRunner:
	def __init__(self, session, graph):
		self.session = session
		self.graph = graph

	# This is *THE* method when we pull a graph, which launches our different 
	# threads to find our edges. We're using threading  because we're making a 
	# bunch of API calls over the Internet.
	def runChecks(self):

		# Huge optimization: figure out the admin users and set "admin" edges
		print('[+] Pulling info on IAM users and roles, finding admins.')
		iamclient = self.session.create_client('iam')
		for node in tqdm(self.graph.nodes, ascii=True, desc='Principals Checked'):
			node.set_admin(principalmap.queries.privesc.PrivEscQuery.check_self(iamclient, node))
		for x in self.graph.nodes:
			for y in self.graph.nodes:
				if x == y:
					continue
				if x.properties['is_admin']:
					self.graph.edges.append(
						AWSEdge(x, y, 'ADMIN')
					)
		print('[+] Finished finding admins.')

		# Create each object to run checks
		checkers = [
			EC2Checker(),
			IAMChecker(),
			LambdaChecker(),
			CloudFormationChecker()
		]
		
		# Run the checks in each checker
		for checker in checkers:
			edgelist = checker.performChecks(self.session, self.graph.nodes)
			self.graph.edges.extend(edgelist)
