"""
An named edge of a graph which represents a relationship between two nodes 
(principals) in an AWS account. nodeX|Y are AWSNode objects.

"""
from __future__ import absolute_import, print_function, unicode_literals


class AWSEdge:
    lookup = {
        'ADMIN': 'can use existing administrative privileges to access',
        'IAM_CREATEKEY': 'can create access keys with IAM to access',
        'IAM_CHANGEPASSWORD': 'can change a password with IAM to access',
        'IAM_CREATEPASSWORD': 'can create a password with IAM to access',
        'STS_ASSUMEROLE': 'can use STS to assume the role',
        'EC2_MAKEPROFILE': 'can create an EC2 instance and create an instance profile to access',
        'EC2_USEPROFILE': 'can create an EC2 instance and use an existing instance profile to access',
        'LAMBDA_CREATEFUNCTION': 'can create a Lambda function and pass an execution role to access',
        'LAMBDA_CHANGEFUNCTIONANDROLE': 'can edit an existing Lambda function and pass an execution role to access',
        'LAMBDA_CHANGEFUNCTIONONLY': 'can edit an existing Lambda function to access',
        'CLOUDFORMATION_OUTPUTCREDS': 'can use keys from the output of a CloudFormation stack to access'
    }

    # support custom labels
    def __init__(self, nodeX, nodeY, shortlabel=None, longlabel=None):
        if shortlabel == None:
            self.shortlabel = 'CUSTOM'
        else:
            self.shortlabel = shortlabel
        if longlabel == None:
            if shortlabel in self.lookup:
                self.longlabel = self.lookup[shortlabel]
            else:
                self.longlabel = 'TODO'
        else:
            self.longlabel = longlabel
        self.nodeX = nodeX
        self.nodeY = nodeY

    def __str__(self):
        return str(self.nodeX) + " -- " + str(self.shortlabel) + " --> " + str(self.nodeY)

    def __repr__(self):
        return repr(self.nodeX) + " " + self.shortlabel + " (" + self.longlabel + ") " + repr(self.nodeY)
