# lambdachecks.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import botocore.session

from .util import *
from principalmap.awsedge import AWSEdge
from tqdm import tqdm

# A class to check if Lambda can be used by a principal to access another principal
class LambdaChecker():
	# regions with Lambda
	regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-1',
	'ap-northeast-2', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1',
	'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'sa-east-1']

	def __init__(self):
		self.functions = None # cache response to reduce API calls

	def performChecks(self, session, nodes):
		print('[+] Starting Lambda checks.')
		iamclient = session.create_client('iam')
		result = []

		self.update_functions(session) # do the expensive task of pulling Lambda functions
		functionarns = []
		for f in self.functions:
			functionarns.append(f['FunctionArn'])
		
		for nodeX in tqdm(nodes, ascii=True, desc='Principals Checked'):
			# skip check for admins
			if nodeX.get_admin():
				continue

			# build a list of passable roles to check
			roles = []
			for nodeY in nodes:
				# skip self-checks
				if nodeY == nodeX:
					continue

				# need to know if nodeY can be passed to Lambda
				if 'lambdaworthy' not in nodeY.tmp:
					nodeY.tmp['lambdaworthy'] = nodeY.get_type() == 'role' and nodeY.chk_trust_document(iamclient, 'lambda.amazonaws.com')
				if nodeY.tmp['lambdaworthy']:
					roles.append(nodeY)
			
			# can nodeX create or invoke an arbitrary lambda?
			create_testresults = testMass(iamclient, nodeX, ['lambda:CreateFunction', 'lambda:InvokeFunction'], ['*'])

			# can nodeX change or invoke existing lambdas?
			change_testresults = testMass(iamclient, nodeX, ['lambda:UpdateFunctionCode', 'lambda:UpdateFunctionConfiguration', 'lambda:InvokeFunction'], functionarns)
			
			# Bail if nodeX can't invoke anything
			invokeskip = True
			createskip = True # for later
			for action, label, allowed in change_testresults + create_testresults:
				if allowed and action == 'lambda:InvokeFunction':
					invokeskip = False
				elif allowed and action == 'lambda:CreateFunction':
					createskip = False
			if invokeskip:
				continue

			# check if nodeX can update existing lambda code to access passed roles
			for action, label, allowed in change_testresults:
				if allowed and action == 'lambda:UpdateFunctionCode':
					targetfunc = None
					for func in self.functions:
						if label == func['FunctionArn']:
							targetfunc = func
							break
					if targetfunc != None and targetfunc['Role'] != '':
						targetrole = None
						for nodeY in roles:
							if nodeY.label == targetfunc['Role']:
								result.append(AWSEdge(nodeX, nodeY, 'LAMBDA_CHANGEFUNCTIONONLY'))

			# Skip passrole checks if nodeX can't create lambdas or update their function configuration
			updateskip = True
			for action, label, allowed in change_testresults:
				if allowed and action == 'lambda:UpdateFunctionConfiguration':
					updateskip = False
					break
			if updateskip and createskip:
				continue
			
			# What can nodeX pass?
			passing_testresults = testMassPass(iamclient, nodeX, roles, 'lambda.amazonaws.com')
			for nodeY in passing_testresults:
				if ('lambda:CreateFunction', '*', True) in create_testresults:
					result.append(AWSEdge(nodeX, nodeY, 'LAMBDA_CREATEFUNCTION'))
				for action, label, allowed in change_testresults:
					if allowed and action == 'lambda:UpdateFunctionConfiguration':
						if ('lambda:UpdateFunctionCode', label, True) in change_testresults:
							result.append(AWSEdge(nodeX, nodeY, 'LAMBDA_CHANGEFUNCTIONANDROLE'))
						
		print('[+] Finished Lambda checks.')
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
			for region in tqdm(LambdaChecker.regions, ascii=True, desc='Regions Checked for Lambda Functions'):
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


