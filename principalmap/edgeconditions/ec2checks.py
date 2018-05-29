# ec2checks.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import botocore.session
import threading
import time

from .util import *
from principalmap.awsedge import AWSEdge

# A class to check if EC2 can be used by a principal to access another
class EC2Checker(threading.Thread):
	def __init__(self, targets, session, graph):
		super(EC2Checker, self).__init__()
		self.targets   = targets
		self.session   = session
		self.graph     = graph

	def run(self):
		print('[+] Starting EC2 checks.')
		for x in self.targets:
			edgelist = self.performChecks(self.session, x[0], x[1])
			self.graph.addedges(edgelist)
			time.sleep(0.25) # dealing with throttle problem
		print('[+] Completed EC2 checks.')

	def performChecks(self, session, nodeX, nodeY):
		iamclient = session.create_client('iam')
		result = []

		if nodeY.get_type() == 'role' and nodeY.chk_trust_document(iamclient, 'ec2.amazonaws.com'):
			if self.chk_ec2_makeprofile(iamclient, nodeX, nodeY):
				result.append(AWSEdge(nodeX, nodeY, 'EC2_MAKEPROFILE'))
			if self.chk_ec2_useprofile(iamclient, nodeX, nodeY):
				result.append(AWSEdge(nodeX, nodeY, 'EC2_USEPROFILE'))

		return result

	# Check 1: Create an instance, create an instance profile and associate
	def chk_ec2_makeprofile(self, iamclient, nodeX, nodeY):
		if testAction(iamclient, nodeX.label, 'ec2:RunInstances') and testAction(iamclient, nodeX.label, 'iam:CreateInstanceProfile') and testAction(iamclient, nodeX.label, 'ec2:AssociateIamInstanceProfile'):
			if testPassRole(iamclient, nodeX, nodeY, 'ec2.amazonaws.com'):
				return True
		return False

	# Check 2: Create an instance, use an existing instance profile and associate
	# Methodology: List instance profiles (with roles) and check perms to associate it.
	def chk_ec2_useprofile(self, iamclient, nodeX, nodeY):
		rolestr = nodeY.get_name()
		response = iamclient.list_instance_profiles_for_role(RoleName=rolestr) # man, this is handy
		if len(response['InstanceProfiles']) > 0:
			if testAction(iamclient, nodeX.label, 'ec2:RunInstances') and testAction(iamclient, nodeX.label, 'ec2:AssociateIamInstanceProfile'):
				if testPassRole(iamclient, nodeX, nodeY, 'ec2.amazonaws.com'):
					return True
		return False




