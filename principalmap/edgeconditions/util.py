# util.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import botocore.session
import re

# For testing actions that require iam:PassRole permission, handles 
# the iam:PassedToService context entry
def testPassRole(iamclient, passer, passed, targetservice):
	context_response = iamclient.get_context_keys_for_principal_policy(PolicySourceArn=passer.label)
	context_entries = []
	if 'iam:PassedToService' in context_response['ContextKeyNames']:
		context_entries.append({
			'ContextKeyName': 'iam:PassedToService',
			'ContextKeyValues': [targetservice],
			'ContextKeyType': 'string'
		})
	response = iamclient.simulate_principal_policy(
		PolicySourceArn=passer.label, 
		ActionNames=['iam:PassRole'], 
		ResourceArns=[passed.label],
		ContextEntries=context_entries
	)
	if 'EvaluationResults' in response and 'EvalDecision' in response['EvaluationResults'][0]:
		return response['EvaluationResults'][0]['EvalDecision'] == 'allowed'

# Generic test action, also accepts ResourceArns
def testAction(client, PolicySourceArn, ActionName, ResourceArn=None, ResourcePolicy=None):
	#print('Checking if ' + PolicySourceArn + ' can do ' + ActionName) # toggle for debug
	context_response = client.get_context_keys_for_principal_policy(PolicySourceArn=PolicySourceArn)
	context_entries = []
	for key in context_response['ContextKeyNames']:
		# TODO: oh god there could be so many context things to deal with (wish it could be done server-side)
		#   might need to consider playing with caching here in the future
		if key == 'aws:username':
			tokens = PolicySourceArn.split('/')
			context_entries.append({
				'ContextKeyName': key,
				'ContextKeyValues': [tokens[len(tokens) - 1]],
				'ContextKeyType': 'string'
			})
	if ResourceArn != None:                                                     
		response = client.simulate_principal_policy(
			PolicySourceArn=PolicySourceArn,
			#CallerArn=PolicySourceArn, 
			ActionNames=[ActionName], 
			ResourceArns=[ResourceArn], 
			ContextEntries=context_entries, 
			#ResourcePolicy=ResourcePolicy
		)
	else:                                                                       
		response = client.simulate_principal_policy(
			PolicySourceArn=PolicySourceArn, 
			#CallerArn=PolicySourceArn,
			ActionNames=[ActionName], 
			ContextEntries=context_entries, 
			#ResourcePolicy=ResourcePolicy
		)

	if 'EvaluationResults' in response:                                         
		if 'EvalDecision' in response['EvaluationResults'][0]:                  
			return response['EvaluationResults'][0]['EvalDecision'] == 'allowed'
	raise Exception('Failed to get a response when simulating a policy')

# Tests actions while trying to pull resource policies when applicable
# Returns result from testAction if the service doesn't use resource policies
def getResourcePolicy(session, ResourceArn):
	service = getServiceFromArn(ResourceArn)
	iamclient = session.create_client('iam')
	# bucket policies
	if service == 's3':
		s3client = session.create_client('s3') # TODO: Update example policy for s3:GetBucketPolicy
		result = re.match(r'arn:[^:]+:s3:::([^/]+)', ResourceArn)
		if result == None:
			raise ValueError("Invalid S3 bucket or object ARN")
		bucket = result.group(1)
		return s3client.get_bucket_policy(Bucket=bucket)['Policy']
	# key policies
	elif service == 'kms':
		kmsclient = session.create_client('kms') # TODO: Update example policy for kms:GetKeyPolicy
		return kmsclient.get_key_policy(KeyId=ResourceArn, PolicyName='default')['Policy']
	#TODO: extend
	else:
		return None

# Grab the service the resource belongs to
# pattern is arn:partition:service:region:account_id:resource
def getServiceFromArn(inputstr):
	tokens = inputstr.split(':')
	if len(tokens) < 6:
		raise ValueError("Invalid ARN")

	return tokens[2]

