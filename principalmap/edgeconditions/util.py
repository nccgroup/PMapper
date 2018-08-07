# util.py
# TODO: Convert comments to PEP257 docstrings (Sphinx), refactor method naming to lowercase_underscores

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
import re
import time

import botocore.session

# Takes a response from the simulate API, returns if a given action and 
# optional resource is allowed or not
# Note: this is only working when the simulation only uses the * resource, due 
# ... to how multiple resources get tossed into ResourceSpecificResults
def findInEvalResults(response, action, resource):
	for result in response['EvaluationResults']:
		if action == result['EvalActionName'] and resource == result['EvalResourceName']:
			return result['EvalDecision'] == 'allowed'
	return False
	
def test_node_access(iamclient, node, actionList, resourceList=None):
	""" Go through each action and resource to determine if the passed AWSNode 
	has permission for the combination. Performs at least one Simulate API call 
	for each action. Breaks down large resourceLists to chunks of twenty and 
	calls separate Simulate API calls per chunk.

	:param botocore.client.IAM iamclient: A Botocore client that can call the AWS IAM API
	:param principalmap.awsnode.AWSNode: An AWSNode representing some principal
	:param list actionList: A list of strings for actions in AWS (service:ActionName convention)
	:param resourceList: A list of strings for ARNs to check access to (optional)
	:type resourceList: list or None
	:return A list of tuples (str, str, bool) for each action/resource/allowed combination.
	:rtype list
	:raises ValueError: if the action list is empty or larger than twenty strings
	"""
	result = []
	if actionList == None or len(actionList) > 20 or len(actionList) == 0:
		raise ValueError('Parameter "actionList" needs to include at least one action, but no more than twenty.')
	if resourceList == None or len(resourceList) < 1:
		resourceList = ['*']
	
	for action in actionList:
		if len(resourceList) > 20:
			resourceListList = []
			x = 0
			y = 20
			while x != len(resourceList): # chunk list into lists of twenty, Python 2/3-agnostic solution
				if y > len(resourceList):
					y = len(resourceList)
				resourceListList.append(resourceList[x:y])
				x += 20
				y += 20
				if x > len(resourceList):
					x = len(resourceList)
			for rlist in resourceListList:
				result.extend(_test_less(iamclient, node, action, rlist))
		else:
			result.extend(_test_less(iamclient, node, action, resourceList))

	return result

def _test_less(iamclient, node, action, resourceList):
	""" (Internal) Test if a passed node can perform a given action on a list of resources."""
	result = []
	response = None
	done = False

	while not done:
		try:
			response = iamclient.simulate_principal_policy(
				PolicySourceArn=node.label,
				ActionNames=[action],
				ResourceArns=resourceList
			)
			done = True
		except ThrottlingException as ex:
			print('ThrottlingException hit, pausing execution for one second.')
			time.sleep(1) # TODO: implement escalate and backoff behavior
		except Exception as ex:
			raise(ex) # Unhandled, raise for debugging

	if len(resourceList) > 1:
		result.extend(_extract_resource_specific_results(response))
	else:
		result.extend(_extract_results(response))

	return result

def _extract_results(response):
	""" (Internal) Create and return a tuple in a list (str, str, bool) for action, resource, and allowed.
	Used for when only one resource (or wildcard) is passed in a Simulate API call.
	"""
	result = []
	for evalresult in response['EvaluationResults']:
		result.append(
			(evalresult['EvalActionName'], evalresult['EvalResourceName'], evalresult['EvalDecision'] == 'allowed')
		)
	return result

def _extract_resource_specific_results(response):
	""" (Internal) Create and return tuples in a list (str, str, bool) for action, resource, and allowed.
	Used for when more than one resource (ARN) is specified for a Simulate API call.
	"""
	result = []
	for evalresult in response['EvaluationResults']:
		action = evalresult['EvalActionName']
		for resourcespecificresult in evalresult['ResourceSpecificResults']:
			result.append(
				(action, resourcespecificresult['EvalResourceName'], resourcespecificresult['EvalResourceDecision'] == 'allowed')
			)
	return result


# For mass-testing of actions and resources
# Takes an IAM client, an AWSNode, a list of string, and a list of string
# Returns a list of tuple, (string, string, bool), for action, resource, and allow/deny for each
# ... action and resource tested.
# TODO: could probably get more code-reuse done here
def testMass(iamclient, node, actionlist, resourcelist):
	result = []
	# Handle ResourceSpecificResults
	if len(resourcelist) > 1:
		response = iamclient.simulate_principal_policy(
			PolicySourceArn=node.label,
			ActionNames=actionlist,
			ResourceArns=resourcelist
		)
		_extractResourceResults(response, result)
		while response['IsTruncated']:
			response = iamclient.simulate_principal_policy(
				PolicySourceArn=node.label,
				ActionNames=actionlist,
				ResourceArns=resourcelist,
				Marker=response['Marker']
			)
			_extractResourceResults(response, result)
	
	# Handle one or no resources
	else:
		if len(resourcelist) == 0:
			resourcelist = ['*']
		response = iamclient.simulate_principal_policy(
			PolicySourceArn=node.label,
			ActionNames=actionlist,
			ResourceArns=resourcelist
		)
		_extractResults(response, result)
		while response['IsTruncated']:
			response = iamclient.simulate_principal_policy(
				PolicySourceArn=node.label,
				ActionNames=actionlist,
				ResourceArns=resourcelist,
				Marker=response['Marker']
			)
			_extractResults(response, result)

	return result

# internal method: modifies result in-place with new action/resource/bool tuples
# using this for multi-resource calls to testMass
def _extractResourceResults(response, result):
	for evalresult in response['EvaluationResults']:
		action = evalresult['EvalActionName']
		for resourcespecificresult in evalresult['ResourceSpecificResults']:
			x = (action, resourcespecificresult['EvalResourceName'], resourcespecificresult['EvalResourceDecision'] == 'allowed')
			if x not in result:
				result.append(x)

# internal method: modifies result in-place with new action/resource/bool tuples
# using this for single-resource calls to testMass (no need for searching resourcespecificresults)
def _extractResults(response, result):
	for evalresult in response['EvaluationResults']:
		x = (evalresult['EvalActionName'], evalresult['EvalResourceName'], evalresult['EvalDecision'] == 'allowed')
		if x not in result:
			result.append(x)

# For mass-testing of iam:PassRole permissions
# Takes an IAM client, an AWSNode, a list of AWSNode, and a string
# Returns a list of AWSNode (passer can pass each one to the service)
# TODO: Handle truncated results
def testMassPass(iamclient, passer, candidates, service):
	if len(candidates) == 0:
		return []
	arnlist = []
	results = []
	for candidate in candidates:
		arnlist.append(candidate.label)
	context_entries = [{
		'ContextKeyName': 'iam:PassedToService',
		'ContextKeyValues': [service],
		'ContextKeyType': 'string'
	}]
	response = iamclient.simulate_principal_policy(
		PolicySourceArn=passer.label,
		ActionNames=['iam:PassRole'],
		ResourceArns=arnlist,
		ContextEntries=context_entries
	)
	results.extend(_extractPassResults(response, candidates))
	while response['IsTruncated']:
		response = iamclient.simulate_principal_policy(
			PolicySourceArn=passer.label,
			ActionNames=['iam:PassRole'],
			ResourceArns=arnlist,
			ContextEntries=context_entries,
			Marker=response['Marker']
		)
		results.extend(_extractPassResults(response, candidates))

	return results

def _extractPassResults(response, candidates):
	result = []
	for candidate in candidates:
		for rsr in response['EvaluationResults'][0]['ResourceSpecificResults']:
			if candidate.label == rsr['EvalResourceName'] and rsr['EvalResourceDecision'] == 'allowed':
				result.append(candidate)
	return result

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

