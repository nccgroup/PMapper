# iamchecks.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import botocore.session
import re

from .util import *
from principalmap.awsedge import AWSEdge
from tqdm import tqdm

# A class to check if IAM can be used by a principal to access another principal
class IAMChecker():
    def __init__(self):
        pass

    def performChecks(self, session, nodes):
        print('[+] Started IAM checks.')
        iamclient = session.create_client('iam')
        result = []

        # for each principal
        for nodeX in tqdm(nodes, ascii=True, desc='Principals Checked'):
            # skip checks for admins
            if nodeX.get_admin():
                continue
            
            # build a list of role ARNs and a list of user ARNs
            users = []
            roles = []
            for nodeY in nodes:
                # skip checks for self
                if nodeX == nodeY:
                    continue
                if nodeY.get_type() == 'user':
                    users.append(nodeY.label)
                elif nodeY.get_type() == 'role' and (nodeY.chk_trust_document(iamclient, nodeX.label) or nodeY.chk_trust_document(iamclient, nodeX.get_root_acct_str())):
                    roles.append(nodeY.label)

            # Simulate actions for users
            if len(users) > 0:
                resultlist = test_node_access(iamclient, nodeX, ['iam:CreateAccessKey', 'iam:UpdateLoginProfile', 'iam:CreateLoginProfile'], users)
                for action, label, allowed in resultlist:
                    if allowed:
                        nodeY = _findNode(label, nodes)
                        if action == 'iam:CreateAccessKey':
                            result.append(AWSEdge(nodeX, nodeY, 'IAM_CREATEKEY'))
                        elif action == 'iam:UpdateLoginProfile':
                            result.append(AWSEdge(nodeX, nodeY, 'IAM_CHANGEPASSWORD'))
                        elif action == 'iam:CreateLoginProfile':
                            result.append(AWSEdge(nodeX, nodeY, 'IAM_CREATEPASSWORD')) # TODO: check if target has password to change
            if len(roles) > 0:
                resultlist = test_node_access(iamclient, nodeX, ['sts:AssumeRole'], roles)
                for action, label, allowed in resultlist:
                    if allowed:
                        nodeY = _findNode(label, nodes)
                        result.append(AWSEdge(nodeX, nodeY, 'STS_ASSUMEROLE'))

        
        print('[+] Finished IAM checks.')
        return result
        
# find an AWSNode by its label
def _findNode(label, nodes):
    for node in nodes:
        if node.label == label:
            return node
    raise RuntimeError('Failed to match a label with an AWSNode.')
