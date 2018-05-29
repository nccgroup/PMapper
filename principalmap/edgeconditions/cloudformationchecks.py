# cloudformationchecks.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import botocore.session
import re
import threading
import time

from .util import *
from principalmap.awsedge import AWSEdge

# A class to check if CloudFormation can be used to access principals
class CloudFormationChecker(threading.Thread):
	regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-1',
    	'ap-northeast-2', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1',
	    'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'sa-east-1']

	def __init__(self, nodes, session, graph):
		super(CloudFormationChecker, self).__init__()
		self.nodes   = nodes
		self.session = session
		self.graph   = graph

	def run(self):
		print('[+] Starting CloudFormation checks.')
		edgelist = self.performChecks()
		self.graph.addedges(edgelist)
		print('[+] Completed CloudFormation checks.')

	def performChecks(self):
		result = []
		userstackpairs = []
		accesskeypattern = re.compile(r"^[A-Z0-9]{20}$")
		secretkeypattern = re.compile(r"^[A-Za-z0-9+/]{40}$")

		# Need to grab/validate all potential creds, track the stack they 
		# belong to, see if anyone has perms to access said stack

		for region in CloudFormationChecker.regions: # for each region...
			cfclient = self.session.create_client('cloudformation', region_name=region)
			stacklist = cfclient.list_stacks()
			for item in stacklist['StackSummaries']: # for each stack...
				fullstacks = cfclient.describe_stacks(StackName=item['StackId'])
				for stack in fullstacks['Stacks']:
					potentialaccesskeys = []
					potentialsecretkeys = []
					if 'Outputs' in stack:
						for output in stack['Outputs']:
							if accesskeypattern.match(output['OutputValue']) != None:
								potentialaccesskeys.append(output['OutputValue'])
							elif secretkeypattern.match(output['OutputValue']) != None:
								potentialsecretkeys.append(output['OutputValue'])
						for accesskey in potentialaccesskeys:
							for secretkey in potentialsecretkeys:
								stsclient = self.session.create_client('sts', aws_access_key_id=accesskey, aws_secret_access_key=secretkey)
								try:
									stsresult = stsclient.get_caller_identity()
									userstackpairs.append((stsresult['Arn'], item['StackId']))
								except:
									pass
		
		iamclient = self.session.create_client('iam')
		for nodeX in self.nodes:
			for pair in userstackpairs:
				if testAction(iamclient, nodeX.label, 'cloudformation:DescribeStacks', ResourceArn=pair[1]):
					for nodeY in self.nodes:
						if nodeX == nodeY:
							continue
						if ':role/aws-service-role' in nodeX.label or ':role/aws-service-role' in nodeY.label:
							continue
						if nodeY.label == pair[0]:
							result.append(AWSEdge(nodeX, nodeY, 'CLOUDFORMATION_OUTPUTCREDS'))
				time.sleep(0.25) # mitigate throttle problems

		return result
