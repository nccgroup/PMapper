# Principal Mapper

A project to speed up the process of reviewing an AWS account's IAM 
configuration.

## Purpose

The goal of the AWS IAM auth system is to apply and enforce access controls 
on actions and resources in AWS. This tool helps identify if the policies in 
place will accomplish the intents of the account's owners. 

AWS already has tooling in place to check if policies attached to a resource 
will permit an action. This tool builds on that functionality to identify 
other potential paths for a user to get access to a resource. This means 
checking for access to other users, roles, and services as ways to pivot. 

## How to Use

1. Download this repository and install its dependencies with
`pip install -r requirements.txt` .
2. Ensure you have graphviz installed on your host.
3. Setup an IAM user in your AWS account with a policy that grants the 
necessary permission to run this tool (see the file mapper-policy.json for an 
example). The ReadOnlyAccess managed policy works for this purpose. Grab the 
access keys created for this user.
4. In the AWS CLI, set up a profile for that IAM user with the command:
`aws configure --profile <profile_name>` where `<profile_name>` is a unique name.
5. Run the command `python pmapper.py --profile <profile_name> graph`
to begin pulling data about your account down to your computer. 

## Graphing

Principal Mapper has a `graph` subcommand, which does the heavy work of going 
through each principal in an account and finding any other principals it can 
access. The results are stored at ~/.principalmap and used by other 
subcommands.

## Querying

Principal Mapper has a `query` subcommand that runs a user-defined query. The 
queries can check if one or more principals can do a given action with a given 
resource. The supported queries are:

```
"can <Principal> do <Action> [with <Resource>]"
"who can do <Action> [with <Resource>]"
"preset <preset_query_name> <preset_query_args>"
```

The first form checks if a principal, or any other principal accessible to it, 
could perform an action with a resource (default wildcard). The second form 
enumerates all principals that are able to perform an action with a resource.

**Note** the quotes around the full query, that's so the argument parser knows to 
take the whole string.

**Note** that `<Principal>` can either be the full ARN of a principal or the 
last part of that ARN (user/... or role/...).

### Presets

The existing preset is `priv_esc` or `change_perms`, which have the same 
function. They describe which principals have the ability to change their own 
permissions. If a principal is able to change their own perms, then it 
effectively has unlimited perms.

## Visualizing

The `visualize` subcommand produces a DOT and SVG file that represent the nodes 
and edges that were graphed. 

To create the DOT and SVG files, run the command:
`python pmapper.py visualize`

Currently the output is a directed graph, which collates all the edges with 
the same source and destination nodes. It does not draw edges where the source 
is an admin. Nodes for admins are colored blue. Nodes for users with the 
ability to access admins are colored red (potential priv-esc risk).

## Sample Output

### Pulling a graph

```
esteringer@ubuntu:~/Documents/projects/Skywalker$ python pmapper.py graph
Using profile: skywalker
Pulling data for account [REDACTED]
Using principal with ARN arn:aws:iam::[REDACTED]:user/TestingSkywalker
[+] Starting EC2 checks.
[+] Starting IAM checks.
[+] Starting Lambda checks.
[+] Starting CloudFormation checks.
[+] Completed CloudFormation checks.
[+] Completed EC2 checks.
[+] Completed Lambda checks.
[+] Completed IAM checks.
Created an AWS Graph with 16 nodes and 53 edges
[NODES]
AWSNode("arn:aws:iam::[REDACTED]:user/AdminUser", properties={u'is_admin': True, u'type': u'user'})
AWSNode("arn:aws:iam::[REDACTED]:user/EC2Manager", properties={u'is_admin': False, u'type': u'user'})
AWSNode("arn:aws:iam::[REDACTED]:user/LambdaDeveloper", properties={u'is_admin': False, u'type': u'user'})
AWSNode("arn:aws:iam::[REDACTED]:user/LambdaFullAccess", properties={u'is_admin': False, u'type': u'user'})
AWSNode("arn:aws:iam::[REDACTED]:user/PowerUser", properties={u'is_admin': False, u'rootstr': u'arn:aws:iam::[REDACTED]:root', u'type': u'user'})
AWSNode("arn:aws:iam::[REDACTED]:user/S3ManagementUser", properties={u'is_admin': False, u'type': u'user'})
AWSNode("arn:aws:iam::[REDACTED]:user/S3ReadOnly", properties={u'is_admin': False, u'type': u'user'})
AWSNode("arn:aws:iam::[REDACTED]:user/TestingSkywalker", properties={u'is_admin': False, u'type': u'user'})
AWSNode("arn:aws:iam::[REDACTED]:role/AssumableRole", properties={u'is_admin': False, u'type': u'role', u'name': u'AssumableRole'})
AWSNode("arn:aws:iam::[REDACTED]:role/EC2-Fleet-Manager", properties={u'is_admin': False, u'type': u'role', u'name': u'EC2-Fleet-Manager'})
AWSNode("arn:aws:iam::[REDACTED]:role/EC2Role-Admin", properties={u'is_admin': True, u'type': u'role', u'name': u'EC2Role-Admin'})
AWSNode("arn:aws:iam::[REDACTED]:role/EC2WithS3ReadOnly", properties={u'is_admin': False, u'type': u'role', u'name': u'EC2WithS3ReadOnly'})
AWSNode("arn:aws:iam::[REDACTED]:role/EMR-Service-Role", properties={u'is_admin': False, u'type': u'role', u'name': u'EMR-Service-Role'})
AWSNode("arn:aws:iam::[REDACTED]:role/LambdaRole-S3ReadOnly", properties={u'is_admin': False, u'type': u'role', u'name': u'LambdaRole-S3ReadOnly'})
AWSNode("arn:aws:iam::[REDACTED]:role/ReadOnlyWithLambda", properties={u'is_admin': False, u'type': u'role', u'name': u'ReadOnlyWithLambda'})
AWSNode("arn:aws:iam::[REDACTED]:role/UpdateCredentials", properties={u'is_admin': False, u'type': u'role', u'name': u'UpdateCredentials'})
[EDGES]
(0,1,'ADMIN','can use existing administrative privileges to access')
(0,2,'ADMIN','can use existing administrative privileges to access')
(0,3,'ADMIN','can use existing administrative privileges to access')
(0,4,'ADMIN','can use existing administrative privileges to access')
(0,5,'ADMIN','can use existing administrative privileges to access')
(0,6,'ADMIN','can use existing administrative privileges to access')
(0,7,'ADMIN','can use existing administrative privileges to access')
(0,8,'ADMIN','can use existing administrative privileges to access')
(0,9,'ADMIN','can use existing administrative privileges to access')
(0,10,'ADMIN','can use existing administrative privileges to access')
(0,11,'ADMIN','can use existing administrative privileges to access')
(0,12,'ADMIN','can use existing administrative privileges to access')
(0,13,'ADMIN','can use existing administrative privileges to access')
(0,14,'ADMIN','can use existing administrative privileges to access')
(0,15,'ADMIN','can use existing administrative privileges to access')
(10,0,'ADMIN','can use existing administrative privileges to access')
(10,1,'ADMIN','can use existing administrative privileges to access')
(10,2,'ADMIN','can use existing administrative privileges to access')
(10,3,'ADMIN','can use existing administrative privileges to access')
(10,4,'ADMIN','can use existing administrative privileges to access')
(10,5,'ADMIN','can use existing administrative privileges to access')
(10,6,'ADMIN','can use existing administrative privileges to access')
(10,7,'ADMIN','can use existing administrative privileges to access')
(10,8,'ADMIN','can use existing administrative privileges to access')
(10,9,'ADMIN','can use existing administrative privileges to access')
(10,11,'ADMIN','can use existing administrative privileges to access')
(10,12,'ADMIN','can use existing administrative privileges to access')
(10,13,'ADMIN','can use existing administrative privileges to access')
(10,14,'ADMIN','can use existing administrative privileges to access')
(10,15,'ADMIN','can use existing administrative privileges to access')
(1,9,'EC2_USEPROFILE','can create an EC2 instance and use an existing instance profile to access')
(1,10,'EC2_USEPROFILE','can create an EC2 instance and use an existing instance profile to access')
(1,11,'EC2_USEPROFILE','can create an EC2 instance and use an existing instance profile to access')
(4,9,'EC2_USEPROFILE','can create an EC2 instance and use an existing instance profile to access')
(4,10,'EC2_USEPROFILE','can create an EC2 instance and use an existing instance profile to access')
(4,11,'EC2_USEPROFILE','can create an EC2 instance and use an existing instance profile to access')
(3,13,'LAMBDA_CREATEFUNCTION','can create a Lambda function and pass an execution role to access')
(3,14,'LAMBDA_CREATEFUNCTION','can create a Lambda function and pass an execution role to access')
(3,15,'LAMBDA_CREATEFUNCTION','can create a Lambda function and pass an execution role to access')
(9,10,'EC2_USEPROFILE','can create an EC2 instance and use an existing instance profile to access')
(4,13,'LAMBDA_CREATEFUNCTION','can create a Lambda function and pass an execution role to access')
(9,11,'EC2_USEPROFILE','can create an EC2 instance and use an existing instance profile to access')
(4,8,'STS_ASSUMEROLE','can use STS to assume the role')
(4,14,'LAMBDA_CREATEFUNCTION','can create a Lambda function and pass an execution role to access')
(4,15,'LAMBDA_CREATEFUNCTION','can create a Lambda function and pass an execution role to access')
(15,0,'IAM_CREATEKEY','can create access keys with IAM to access')
(15,1,'IAM_CREATEKEY','can create access keys with IAM to access')
(15,2,'IAM_CREATEKEY','can create access keys with IAM to access')
(15,3,'IAM_CREATEKEY','can create access keys with IAM to access')
(15,4,'IAM_CREATEKEY','can create access keys with IAM to access')
(15,5,'IAM_CREATEKEY','can create access keys with IAM to access')
(15,6,'IAM_CREATEKEY','can create access keys with IAM to access')
(15,7,'IAM_CREATEKEY','can create access keys with IAM to access')

```

### Querying with the graph

```
esteringer@ubuntu:~/Documents/projects/Skywalker$ ./pmapper.py --profile skywalker query "who can do s3:GetObject with *"
user/AdminUser can do s3:GetObject with *
user/EC2Manager can do s3:GetObject with * through role/EC2Role-Admin
   user/EC2Manager can create an EC2 instance and use an existing instance profile to access role/EC2Role-Admin
role/EC2Role-Admin can do s3:GetObject with *
user/LambdaFullAccess can do s3:GetObject with *
user/PowerUser can do s3:GetObject with *
user/S3ManagementUser can do s3:GetObject with *
user/S3ReadOnly can do s3:GetObject with *
user/TestingSkywalker can do s3:GetObject with *
role/EC2-Fleet-Manager can do s3:GetObject with * through role/EC2Role-Admin
	role/EC2-Fleet-Manager can create an EC2 instance and use an existing instance profile to access role/EC2Role-Admin
role/EC2Role-Admin can do s3:GetObject with *
role/EC2Role-Admin can do s3:GetObject with *
role/EC2WithS3ReadOnly can do s3:GetObject with *
role/EMR-Service-Role can do s3:GetObject with *
role/LambdaRole-S3ReadOnly can do s3:GetObject with *
role/UpdateCredentials can do s3:GetObject with * through user/AdminUser
	role/UpdateCredentials can create access keys with IAM to access user/AdminUser
user/AdminUser can do s3:GetObject with *
```

### Identifying Potential Privilege Escalation

```
esteringer@ubuntu:~/Documents/projects/Skywalker$ ./pmapper.py --profile skywalker query "preset priv_esc user/PowerUser"
Discovered a potential path to change privileges:
user/PowerUser can change privileges because:
	user/PowerUser can access role/EC2Role-Admin because: 
		user/PowerUser can create an EC2 instance and use an existing instance profile to access role/EC2Role-Admin
	and role/EC2Role-Admin can change its own privileges.

```

### Sample Visualization

![Example output from visualize subcommand](/example_output.png)

## Planned TODOs

* Complete and verify Python 3 support.
* Smarter control over rate of API requests (Queue, managing throttles).
* Better progress reporting.
* Validate and add more checks for obtaining credentials. Several services use
service roles that grant the service permission to do an action within a user's 
account. This could potentially allow a user to obtain access to additional 
privileges. 
* Improving simulate calls (global conditions).
* Completing priv esc checks (editing attached policies, attaching to a group).
* Adding options for visualization (output type, edge collation).
* Adding more caching. 
* Local policy evaluation?
* Cross-account subcommand(s).
* A preset to check if one principal is connected to another.
* Handling policies for buckets or keys with services like S3 or KMS when 
querying.

