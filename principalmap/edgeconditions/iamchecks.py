# iamchecks.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import botocore.session
import re
import threading
import time

from .util import *
from principalmap.awsedge import AWSEdge

# A class to check if IAM can be used by a principal to access another
class IAMChecker(threading.Thread):
	def __init__(self, targets, session, graph):
		super(IAMChecker, self).__init__()
		self.targets = targets
		self.session = session
		self.graph   = graph

	def run(self):
		print('[+] Starting IAM checks.')
		for x in self.targets:
			edgelist = self.performChecks(self.session, x[0], x[1])
			self.graph.addedges(edgelist)
			time.sleep(0.2) # throttle is killing me
		print('[+] Completed IAM checks.')

	def performChecks(self, session, nodeX, nodeY):
		iamclient = session.create_client('iam')
		result = []

		# Check 1: CreateAccessKey for User
		if nodeY.get_type() == 'user':
			if testAction(iamclient, nodeX.label, 'iam:CreateAccessKey', ResourceArn=nodeY.label):
				result.append(AWSEdge(nodeX, nodeY, 'IAM_CREATEKEY'))

		# Check 2: AssumeRole for Role
		if nodeY.get_type() == 'role':
			if testAction(iamclient, nodeX.label, 'sts:AssumeRole', ResourceArn=nodeY.label):
				# Check AssumeRolePolicyDocument
				if nodeY.chk_trust_document(iamclient, nodeX.label) or nodeY.chk_trust_document(iamclient, nodeX.get_root_acct_str()):
					result.append(AWSEdge(nodeX, nodeY, 'STS_ASSUMEROLE'))

		# Check 3: UpdateLoginProfile for User
		# TODO: User has to have a password already, see CreateLoginProfile otherwise
		# TODO: Consider MFA?
		if nodeY.get_type() == 'user':
			if testAction(iamclient, nodeX.label, 'iam:UpdateLoginProfile', ResourceArn=nodeY.label):
				result.append(AWSEdge(nodeX, nodeY, 'IAM_CHANGEPASSWORD'))

		return result
