# ec2checks.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import botocore.session

from .util import *
from principalmap.awsedge import AWSEdge
from tqdm import tqdm

# A class to check if EC2 can be used by a principal to access another principal
class EC2Checker():
    def __init__(self):
        pass

    def performChecks(self, session, nodes):
        print('[+] Started EC2 checks.')
        iamclient = session.create_client('iam')
        result = []

        for nodeX in tqdm(nodes, ascii=True, desc='Principals Checked'):
            # skip checks for admins
            if nodeX.get_admin():
                continue

            # build a list of passable roles
            withprofiles = []
            withoutprofiles = []
            for nodeY in nodes:
                # skip self-checks
                if nodeY == nodeX:
                    continue

                # need to know if nodeY is a role can be passed to EC2, and if it has an instance profile. cache results.
                if 'ec2worthy' not in nodeY.tmp:
                    nodeY.tmp['ec2worthy'] = nodeY.get_type() == 'role' and nodeY.chk_trust_document(iamclient, 'ec2.amazonaws.com')
                if nodeY.tmp['ec2worthy']:
                    if 'instance_profile' not in nodeY.tmp: 
                        response = iamclient.list_instance_profiles_for_role(RoleName=nodeY.get_name())
                        nodeY.tmp['instance_profile'] = len(response['InstanceProfiles']) > 0
                    if nodeY.tmp['instance_profile']:
                        withprofiles.append(nodeY)
                    else:
                        withoutprofiles.append(nodeY)
            
            # bail if we don't have candidates, save the API calls
            if len(withprofiles) + len(withoutprofiles) == 0:
                continue
            
            # with a list of passable roles, check if nodeX can do the necessary actions
            response = iamclient.simulate_principal_policy(
                PolicySourceArn=nodeX.label,
                ActionNames=['ec2:RunInstances', 'ec2:AssociateIamInstanceProfile', 'iam:CreateInstanceProfile'],
            )
            can_run = findInEvalResults(response, 'ec2:RunInstances', '*')
            can_associate = findInEvalResults(response, 'ec2:AssociateIamInstanceProfile', '*')
            can_create = findInEvalResults(response, 'iam:CreateInstanceProfile', '*')

            # if nodeX can run and associate, check what it can pass. add edges
            if can_run and can_associate:
                if can_create and len(withoutprofiles) > 0:
                    passable = testMassPass(iamclient, nodeX, withoutprofiles, 'ec2.amazonaws.com')
                    for nodeY in passable:
                        result.append(AWSEdge(nodeX, nodeY, 'EC2_MAKEPROFILE'))
                if len(withprofiles) > 0:
                    passable = testMassPass(iamclient, nodeX, withprofiles, 'ec2.amazonaws.com')
                    for nodeY in passable:
                        result.append(AWSEdge(nodeX, nodeY, 'EC2_USEPROFILE'))
                        
        print('[+] Finished EC2 checks.')
        return result

