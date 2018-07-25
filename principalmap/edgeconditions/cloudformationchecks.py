# cloudformationchecks.py

from __future__ import absolute_import, print_function, unicode_literals

from tqdm import tqdm

from principalmap.awsedge import AWSEdge
from .util import *


# A class to check if CloudFormation can be used to access principals
class CloudFormationChecker():
    regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-1',
               'ap-northeast-2', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1',
               'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'sa-east-1']

    def performChecks(self, session, nodes):
        print('[+] Starting CloudFormation checks.')
        result = []
        userstackpairs = []
        accesskeypattern = re.compile(r"^[A-Z0-9]{20}$")
        secretkeypattern = re.compile(r"^[A-Za-z0-9+/]{40}$")

        # Need to grab/validate all potential creds, track the stack they
        # belong to, see if anyone has perms to access said stack

        for region in tqdm(CloudFormationChecker.regions, ascii=True,
                           desc='CloudFormation Regions Checked'):  # for each region...
            cfclient = session.create_client('cloudformation', region_name=region)
            stacklist = cfclient.list_stacks()
            for item in stacklist['StackSummaries']:  # for each stack...
                fullstacks = cfclient.describe_stacks(StackName=item['StackId'])  # TODO this gets throttled when too many stacks
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
                                stsclient = session.create_client('sts', aws_access_key_id=accesskey,
                                                                  aws_secret_access_key=secretkey)
                                try:
                                    stsresult = stsclient.get_caller_identity()
                                    userstackpairs.append((stsresult['Arn'], item['StackId']))
                                except:
                                    pass

        iamclient = session.create_client('iam')
        for nodeX in tqdm(nodes, ascii=True, desc='Principals Checked'):
            if nodeX.get_admin():
                continue
            for pair in userstackpairs:
                if testAction(iamclient, nodeX.label, 'cloudformation:DescribeStacks', ResourceArn=pair[1]):
                    for nodeY in nodes:
                        if nodeX == nodeY:
                            continue
                        if nodeY.label == pair[0]:
                            result.append(AWSEdge(nodeX, nodeY, 'CLOUDFORMATION_OUTPUTCREDS'))

        print('[+] Finished CloudFormation checks.')
        return result
