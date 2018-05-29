# Edges

The principals of an AWS account can be represented as nodes in a graph. If a 
principal is able to obtain credentials for another principal, we can represent
that as an edge with a direction. This is how we compose a directed graph to 
determine the complete list of actions and resources that a principal could 
potentially access.

# Obtaining Credentials

This section of code attempts to leverage the IAM simulator to determine if 
each principal of an AWS account has the necessary permissions in order to 
obtain credentials for another principal. One example is the EC2 instance 
profile: a user that can create an instance with a given profile could access 
the credentials for the roles contained within that profile. This is possible 
because when the instance is running, it can access the metadata service and 
obtain a set of temporary credentials for a role (access key id, secret key, 
and a security token).

## IAM and STS

In IAM, a principal can obtain creds through several actions, such as 
changing access keys or passwords for existing users. STS provides APIs to 
obtain credentials for roles that can be assumed by a principal.

This tool will check each principal for access to the following permissions: 

* iam:UpdateLoginProfile
* iam:CreateAccessKey
* sts:AssumeRole

The appropriate resource ARNs are included when making the call to the 
simulator, and the trusted entities are checked when calling sts:AssumeRole.

## EC2

A principal trying to obtain creds through EC2 needs the following perms:

1. Permission to run an instance.
2. Permission to create an instance profile (or use an existing one).
3. Permission to associate an instance profile with an instance.

Relevant documentation: http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html

### Instance Profiles

An instance profile is a bucket that a role can be tossed into. An EC2 instance
with an associated instance profile can access the role associated with the 
profile. There is a limit to one role per instance profile (subject to change 
in the future?). 

When a principal performs RunInstances and specifies an instance profile, there 
is a check that the user has permission to pass the role (iam:PassRole) that's 
in the instance-profile. Similarly, there's a PassRole check done for the 
AssociateIamInstanceProfile action for a running instance. A user looking to 
associate an instance profile needs to have the PassRole permission. The role 
that is meant to be used in an instance profile must have ec2.amazonaws.com as
a trusted entity.

This tool will check each principal to see if they have the following 
permissions to add an existing profile (and role) to an instance:

* ec2:RunInstances
* ec2:AssociateIamInstanceProfile
* iam:PassRole 

It also checks to see if a principal can create a profile and then associate 
the profile with an instance (with a specified role):

* ec2:RunInstances
* ec2:AssociateIamInstanceProfile
* iam:CreateInstanceProfile
* iam:PassRole

## Lambda

Lambda functions can be given an execution role, which empowers the function to
perform actions within an AWS account. A principal could obtain the credentials 
that's used by Lambda when it assumes the role if they're able to specify the 
function's code. This brings up three scenarios:

* A principal is able to create a Lambda function and pass a role to it.
* A principal is able to alter the code of an existing function and pass a new
role as the execution role.
* A principal is able to alter the code of an existing function which already 
has an execution role.

This tool will check if a principal has the permissions needed for these 
actions, such as lambda:CreateFunction, lambda:UpdateFunction, 
lambda:UpdateFunctionConfiguration, lambda:InvokeFunction, and iam:PassRole.

## CloudFormation

CloudFormation can create users along with their associated access keys. The 
only way to retrieve the secret key is through the output of the stack, 
however that means the secret key will be accessible to all principals with 
permission for the action cloudformation:DescribeStacks.

This tool goes through each stack in each region to locate any potential 
access keys and secret keys. Then it will see which principals have the 
permission necessary to see those keys (cloudformation:DescribeStacks).

## Future Work

Future items of interest to improve this code include:

* Going through more services to see where credentials can be grabbed.
* Using a thread pool to process each service.


