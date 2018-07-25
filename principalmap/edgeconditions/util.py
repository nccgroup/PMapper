# util.py

from __future__ import absolute_import, print_function, unicode_literals

import re
import time

# Takes a response from the simulate API, returns if a given action and 
# optional resource is allowed or not
# Note: this is only working when the simulation only uses the * resource, due 
# ... to how multiple resources get tossed into ResourceSpecificResults
def findInEvalResults(response, action, resource):
    for result in response['EvaluationResults']:
        if action == result['EvalActionName'] and resource == result['EvalResourceName']:
            return result['EvalDecision'] == 'allowed'
    return False


# For mass-testing of actions and resources
# Takes an IAM client, an AWSNode, a list of string, and a list of string
# Returns a list of tuple, (string, string, bool), for action, resource, and allow/deny for each
# ... action and resource tested.
# TODO: could probably get more code-reuse done here
def testMass(iamclient, node, actionlist, resourcelist):
    result = []
    try:
        # Handle ResourceSpecificResults
        if len(resourcelist) > 1:
            response = iamclient.simulate_principal_policy(
                PolicySourceArn=node.label,
                ActionNames=actionlist,
                ResourceArns=resourcelist,
                MaxItems=20
            )
            _extractResourceResults(response, result)
            while response['IsTruncated']:
                #  TODO ensure this doesn't cause an infinite loop
                try:
                    response = iamclient.simulate_principal_policy(
                        PolicySourceArn=node.label,
                        ActionNames=actionlist,
                        ResourceArns=resourcelist,
                        Marker=response['Marker'],
                        MaxItems=20
                    )
                    _extractResourceResults(response, result)
                except Exception as e:
                    print('[-] error: %s' % e)
                    time.sleep(15)  # wait for 15 seconds before continuing
                    continue
        # Handle one or no resources
        else:
            if len(resourcelist) == 0:
                resourcelist = ['*']
            response = iamclient.simulate_principal_policy(
                PolicySourceArn=node.label,
                ActionNames=actionlist,
                ResourceArns=resourcelist,
                MaxItems=20
            )
            _extractResults(response, result)
            while response['IsTruncated']:
                try:
                    response = iamclient.simulate_principal_policy(
                        PolicySourceArn=node.label,
                        ActionNames=actionlist,
                        ResourceArns=resourcelist,
                        Marker=response['Marker'],
                        MaxItems=20
                    )
                    _extractResults(response, result)
                except Exception as e:
                    print('[-] error: %s' % e)
                    time.sleep(15)  # wait for 15 seconds before continuing
                    continue
    except Exception as e:
        print('[-] error: %s' % e)


    return result


# internal method: modifies result in-place with new action/resource/bool tuples
# using this for multi-resource calls to testMass
def _extractResourceResults(response, result):
    for evalresult in response['EvaluationResults']:
        action = evalresult['EvalActionName']
        for resourcespecificresult in evalresult['ResourceSpecificResults']:
            x = (action, resourcespecificresult['EvalResourceName'],
                 resourcespecificresult['EvalResourceDecision'] == 'allowed')
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
    for candidate in candidates:
        for resourceresult in response['EvaluationResults'][0]['ResourceSpecificResults']:
            if candidate.label == resourceresult['EvalResourceName'] and resourceresult[
                'EvalResourceDecision'] == 'allowed':
                results.append(candidate)

    return results


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
            # CallerArn=PolicySourceArn,
            ActionNames=[ActionName],
            ResourceArns=[ResourceArn],
            ContextEntries=context_entries,
            # ResourcePolicy=ResourcePolicy
        )
    else:
        response = client.simulate_principal_policy(
            PolicySourceArn=PolicySourceArn,
            # CallerArn=PolicySourceArn,
            ActionNames=[ActionName],
            ContextEntries=context_entries,
            # ResourcePolicy=ResourcePolicy
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
        s3client = session.create_client('s3')  # TODO: Update example policy for s3:GetBucketPolicy
        result = re.match(r'arn:[^:]+:s3:::([^/]+)', ResourceArn)
        if result == None:
            raise ValueError("Invalid S3 bucket or object ARN")
        bucket = result.group(1)
        return s3client.get_bucket_policy(Bucket=bucket)['Policy']
    # key policies
    elif service == 'kms':
        kmsclient = session.create_client('kms')  # TODO: Update example policy for kms:GetKeyPolicy
        return kmsclient.get_key_policy(KeyId=ResourceArn, PolicyName='default')['Policy']
    # TODO: extend
    else:
        return None


# Grab the service the resource belongs to
# pattern is arn:partition:service:region:account_id:resource
def getServiceFromArn(inputstr):
    tokens = inputstr.split(':')
    if len(tokens) < 6:
        raise ValueError("Invalid ARN")

    return tokens[2]
