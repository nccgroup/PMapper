# Principal Mapper

A program for identifying risks in the configuration of AWS Identity and Access Management (IAM) in an AWS account.

PMapper allows users to identify which IAM users and roles have access to certain actions and resources in an AWS account. This is important for ensuring that sensitive items such as S3 objects with PII are isolated.

PMapper creates a graph of an AWS account's IAM users and roles. This graph, composed of nodes and edges, represents the different ways that one node could access another. When running a query to determine if an IAM user or role has access to a certain action/resource, it also checks if the user or role could access other users or roles that have access to that action/resource. This catches scenarios such as when a user doesn't have direct access to an S3 object, but could launch an EC2 instance that has access to the S3 object.

## Installation

### Requirements

Principal Mapper is built using the `botocore` library and Python3. Python2 is not supported. 

### Installation From Source Code

Clone the repository:

~~~bash
git clone git@github.com:nccgroup/PMapper.git
~~~

Then install with Pip:

~~~bash
cd PMapper
pip install .
~~~

## Usage

### Graphing

To start, create a graph for the account.

~~~bash
pmapper graph --create
~~~

This stores information locally on disk about all the IAM users, roles, groups, and policies in the account.


### Querying

After creating a graph, write queries to learn more about which users and roles can access certain actions or resources.

~~~bash
pmapper argquery --action s3:GetObject --resource arn:aws:s3:::bucket/path/to/object 
~~~

`argquery` takes the elements to check for (principal, action, resource, conditions) as arguments of the `pmapper` command. When `--principal` is not specified, it runs the query for all IAM  users and roles in the account. When `--resource` is not specified, it defaults to the wildcard (`*`).

~~~bash
pmapper query "who can do s3:GetObject with arn:aws:s3:::bucket/path/to/object"
~~~

`query` parses a more human-readable input string into a query and returns the results.

## Credentials

Principal Mapper works with botocore (AWS CLI) profiles when the `--profile` parameter is specified. Additionally, it will use environment variables (`AWS_ACCESS_KEY_ID`) when they are specified.

