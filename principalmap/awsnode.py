# awsnode.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import botocore.session
import re


class AWSNode:
    """
    A named node in a graph which represents a principal in an AWS account.

    The label value returns the full ARN, str() returns a shortened representation.

    We use two fields called properties and tmp to cache information, with the goal of
    reducing the amount of AWS API calls made.
    """

    def __init__(self, label, properties=None):
        self.label = label
        if properties is None:
            self.properties = {}
        else:
            self.properties = properties
        self.fullroleobj = None  # we don't want this cached
        self.tmp = {}  # stash stuff here that will not be added to repr(), for caching

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

    def get_type(self):
        """Return and cache the type of principal this node represents."""
        if 'type' not in self.properties:
            if ':user/' in self.label:
                self.properties['type'] = 'user'
            elif ':role/' in self.label:
                self.properties['type'] = 'role'
            else:
                self.properties['type'] = 'unknown'
        return self.properties['type']

    def get_name(self):
        """Return and cache the name of the principal this node represents."""
        if 'name' not in self.properties:
            tokens = self.label.split('/')
            self.properties['name'] = tokens[len(tokens) - 1]  # better way to grab names
        return self.properties['name']

    # Check if target is a trusted entity to assume a role (full ARN or service host)
    # Caches the trust doc
    # If you want to check if a specific principal can assume, you need to pass the full user/role ARN and the account root ARN
    def chk_trust_document(self, iamclient, assumer):
        """Check if the passed assumer is a trusted entity to assume a role (full ARN or the
        service's host (*.amazonaws.com). Caches the trust document for future calls.
        """
        if self.get_type() != 'role':
            return False

        if self.fullroleobj is None:
            self.fullroleobj = iamclient.get_role(RoleName=self.get_name())

        if 'Role' not in self.fullroleobj:
            return False

        if 'AssumeRolePolicyDocument' not in self.fullroleobj['Role']:
            return False

        trustdocobj = self.fullroleobj['Role']['AssumeRolePolicyDocument']

        if 'Statement' not in trustdocobj:
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
        if 'rootstr' not in self.properties:
            match = re.search(r"arn:aws:iam::(\d{12}):", self.label)
            acctnum = match.group(1)
            self.properties['rootstr'] = 'arn:aws:iam::' + acctnum + ':root'
        return self.properties['rootstr']
