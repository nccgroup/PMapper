# lambdachecks.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import botocore.session
import threading
import time

from .util import *
from principalmap.awsedge import AWSEdge

# A class to check if Lambda can be used by a principal to access another
class LambdaChecker(threading.Thread):
	# regions with Lambda
	regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-1',
	'ap-northeast-2', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1',
	'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'sa-east-1']

	def __init__(self, targets, session, graph):
		super(LambdaChecker, self).__init__()
		self.functions = None # cache response to reduce API calls
		self.targets   = targets
		self.session   = session
		self.graph     = graph
	
	def run(self):
		print('[+] Starting Lambda checks.')
		for x in self.targets:
			edgelist = self.performChecks(self.session, x[0], x[1])
			self.graph.addedges(edgelist)
			time.sleep(0.25) # dealing with throttle
		print('[+] Completed Lambda checks.') 

	def performChecks(self, session, nodeX, nodeY):
		iamclient = session.create_client('iam')
		result = []
		if not nodeY.get_type() == 'role':
			return result
		
		if self.chk_createlambda(iamclient, nodeX, nodeY):
			result.append(AWSEdge(nodeX, nodeY, 'LAMBDA_CREATEFUNCTION'))

		if self.chk_changelambdaandrole(iamclient, session, nodeX, nodeY):
			result.append(AWSEdge(nodeX, nodeY, 'LAMBDA_CHANGEFUNCTIONANDROLE'))
		
		if self.chk_changeonlylambda(iamclient, session, nodeX, nodeY):
			result.append(AWSEdge(nodeX, nodeY, 'LAMBDA_CHANGEFUNCTIONONLY'))

		return result
	

	def chk_createlambda(self, iamclient, nodeX, nodeY):
		if not nodeY.chk_trust_document(iamclient, 'lambda.amazonaws.com'):
			return False

		if testAction(iamclient, nodeX.label, 'lambda:CreateFunction') and testAction(iamclient, nodeX.label, 'lambda:InvokeFunction'):
			if testPassRole(iamclient, nodeX, nodeY, 'lambda.amazonaws.com'):
				return True

		return False

	def chk_changelambdaandrole(self, iamclient, session, nodeX, nodeY):
		if not nodeY.chk_trust_document(iamclient, 'lambda.amazonaws.com'):
			return False

		self.update_functions(session)
		
		for f in self.functions:
			if testAction(iamclient, nodeX.label, 'lambda:UpdateFunctionCode', f['FunctionArn']):
				if testAction(iamclient, nodeX.label, 'lambda:UpdateFunctionConfiguration') and testAction(iamclient, nodeX.label, 'lambda:InvokeFunction'):
					if testPassRole(iamclient, nodeX, nodeY, 'lambda.amazonaws.com'):
						return True

		return False

	def chk_changeonlylambda(self, iamclient, session, nodeX, nodeY):
		if not nodeY.chk_trust_document(iamclient, 'lambda.amazonaws.com'):
			return False

		self.update_functions(session)

		for f in self.functions:
			if not f['Role'] == nodeY.label:
				continue
			if testAction(iamclient, nodeX.label, 'lambda:UpdateFunctionCode', f['FunctionArn']) and testAction(iamclient, nodeX.label, 'lambda:InvokeFunction'):
				return True

		return False

	# This grabs all functions from all regions
	# This is an expensive operation, we try to cache all the results possible
	def update_functions(self, session):
		if self.functions == None:
			self.functions = []
			# Lambda's API didn't return a full list of functions all the time, 
			# so we have to do this expensive pull from each region
			for region in LambdaChecker.regions:
				lambdaclient = session.create_client('lambda', region_name=region)
				response = lambdaclient.list_functions()
				if 'Functions' in response and isinstance(response['Functions'], list):
					for x in response['Functions']:
						addthis = True
						for y in self.functions:
							if x['FunctionArn'] == y['FunctionArn']:
								addthis = False
								break
						if addthis:
							self.functions.extend([x])
				else:
					print('TODO')


