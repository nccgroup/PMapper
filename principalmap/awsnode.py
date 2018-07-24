"""
A named node in a graph which represents a principal in an AWS account.

The label value returns the full ARN, str() returns a shortened representation.

We use two fields called properties and tmp to cache information, with the goal of 
reducing the amount of AWS API calls made.

"""
from __future__ import absolute_import, print_function, unicode_literals

import re

import botocore.session


class AWSNode:
	def __init__(self, label, properties=None):
		self.label = label
		if properties == None:
			self.properties = {}
		else:
			self.properties = properties
		self.fullroleobj = None # we don't want this cached
		self.tmp = {} # stash stuff here that will not be added to repr(), for caching

	def __str__(self):
		return self.get_type() + "/" + self.get_name()

	def __repr__(self):
		return 'AWSNode("' + self.label + '", properties=' + repr(self.properties) + ')'

	def set_admin(self, value):
		self.properties['is_admin'] = value
	
	def get_admin(self):
		if 'is_admin' in self.properties:
			return self.properties['is_admin']
		return None

	# return and cache the type of principal this node represents
	def get_type(self):
		if not 'type' in self.properties:
			if ':user/' in self.label:
				self.properties['type'] = 'user'
			elif ':role/' in self.label:
				self.properties['type'] = 'role'
			else:
				self.properties['type'] = 'unknown'
		return self.properties['type']
			
	
	# return and cache the name of the principal this node represents
	def get_name(self):
		if not 'name' in self.properties:
			tokens = self.label.split('/')
			self.properties['name'] = tokens[len(tokens) - 1] # better way to grab names
		return self.properties['name']
	
	# Check if target is a trusted entity to assume a role (full ARN or service host)
	# Caches the trust doc
	# If you want to check if a specific principal can assume, you need to pass the full user/role ARN and the account root ARN
	def chk_trust_document(self, iamclient, assumer):
		if self.get_type() != 'role':
			return False

		if self.fullroleobj == None:
			self.fullroleobj = iamclient.get_role(RoleName=self.get_name())

		if not 'Role' in self.fullroleobj:
			return False
		
		if not 'AssumeRolePolicyDocument' in self.fullroleobj['Role']:
			return False

		trustdocobj = self.fullroleobj['Role']['AssumeRolePolicyDocument']

		if not 'Statement' in trustdocobj:
			return False

		# TODO: Remove duplicate code
		if isinstance(trustdocobj['Statement'], list):
			for x in trustdocobj['Statement']:
				if 'Principal' in x:
					if 'Effect' in x:
						if x['Effect'] == 'Deny':
							if 'Service' in x['Principal']:
								if x['Principal']['Service'] == assumer:
									return False
							elif 'AWS' in x['Principal']:
								if x['Principal']['AWS'] == assumer:
									return False
						else:
							if 'Service' in x['Principal']:
								if x['Principal']['Service'] == assumer:
									return True
							elif 'AWS' in x['Principal']:
								if x['Principal']['AWS'] == assumer:
									return True
		elif isinstance(trustdocobj['Statement'], dict):
			if 'Principal' in trustdoctobj['Statement'] and 'Effect' in trustdoctobj['Statement']:
				if trustdoctobj['Statement']['Effect'] == 'Deny':
					if 'Service' in trustdoctobj['Statement']['Principal']:
						if trustdoctobj['Statement']['Principal']['Service'] == assumer:
							return False
					elif 'AWS' in trustdoctobj['Statement']['Principal']:
						if trustdoctobj['Statement']['Principal']['AWS'] == assumer:
							return False
				else:
					if 'Service' in trustdoctobj['Statement']['Principal']:
						if trustdoctobj['Statement']['Principal']['Service'] == assumer:
							return True
					elif 'AWS' in trustdoctobj['Statement']['Principal']:
						if trustdoctobj['Statement']['Principal']['AWS'] == assumer:
							return True
		

	def get_root_acct_str(self):
		if not 'rootstr' in self.properties:
			match = re.search(r"arn:aws:iam::(\d{12}):", self.label)
			acctnum = match.group(1)
			self.properties['rootstr'] = 'arn:aws:iam::' + acctnum + ':root'
		return self.properties['rootstr']
